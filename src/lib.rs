mod process_manip;
use core::slice;
use detour::GenericDetour;
use parking_lot::RwLock;
use process_manip::{ModuleSnapshot, PrintWindowOption, PrintWindowResult, ProcessSnapshot};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    ffi::CString,
    fs::{self, File},
    io::{Read, Write},
    iter::once,
    mem,
    net::{Ipv4Addr, TcpStream},
    path::PathBuf,
};
use windows::{
    core::{PCSTR, PCWSTR},
    Win32::{
        Networking::WinSock::{ADDRINFOA, AF_INET, SOCKADDR, SOCKADDR_IN, SOCKET},
        Security::Cryptography::CRYPT_KEY_FLAGS,
        System::LibraryLoader::{GetProcAddress, LoadLibraryW},
    },
};

/// Injector settings
#[derive(Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    /// Path to user provided public key
    user_key: String,
    /// Controls the dumping of sega keys
    grab_keys: bool,
    /// Enables address replacement feature
    replace_address: bool,
    /// Enables auto public key exchange
    auto_key_fetch: bool,
    /// List of addresses to replace
    addresses: Vec<AddrReplace>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            grab_keys: true,
            replace_address: false,
            user_key: "publicKey.blob".to_string(),
            auto_key_fetch: false,
            addresses: vec![AddrReplace::default()],
        }
    }
}

// Ship address to be replaced
#[derive(Serialize, Deserialize)]
struct AddrReplace {
    old: String,
    new: String,
}
impl Default for AddrReplace {
    fn default() -> Self {
        AddrReplace {
            old: "old_address".to_string(),
            new: "new_address".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Keys {
    ip: Ipv4Addr,
    key: Vec<u8>,
}

// consists of BLOBHEADER + RSAPUBKEY.magic
static RSAHEADER: [u8; 12] = [
    0x06, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x31,
];

// scraped RSA keys from the game
static SEGA_RSA_KEYS: RwLock<Vec<Vec<u8>>> = RwLock::new(vec![]);
// user provided RSA key
static USER_RSA_KEY: RwLock<Vec<u8>> = RwLock::new(vec![]);
// RSA keys provided by the server/proxy
static SHIP_RSA_KEYS: RwLock<Vec<Keys>> = RwLock::new(vec![]);
// injector settings
static SETTINGS: RwLock<Option<Settings>> = RwLock::new(None);

// detours for functions
static HOOK_CRYPT_OPEN: RwLock<Option<GenericDetour<CryptImportKeyFn>>> = RwLock::new(None);
static HOOK_GETADDRINFO: RwLock<Option<GenericDetour<GetaddrinfoFn>>> = RwLock::new(None);
static HOOK_CONNECT: RwLock<Option<GenericDetour<ConnectFn>>> = RwLock::new(None);

// path to exe dir
static PATH: RwLock<Option<std::path::PathBuf>> = RwLock::new(None);

type CryptImportKeyFn =
    extern "system" fn(usize, *const u8, u32, usize, CRYPT_KEY_FLAGS, *mut usize) -> bool;
type GetaddrinfoFn = extern "system" fn(PCSTR, PCSTR, *const ADDRINFOA, *mut *mut ADDRINFOA) -> i32;
type ConnectFn = extern "system" fn(SOCKET, *const SOCKADDR, i32) -> i32;

// macro to detour a function
macro_rules! create_hook {
    ($dll_name:expr, $fn_name:expr => $new_fn:ident: $fn_type:ty) => {
        (|| -> Result<GenericDetour<_>, Box<dyn Error>> {
            let dll_name_u16: Vec<u16> = $dll_name.encode_utf16().chain(once(0)).collect();
            let fn_name_u8: Vec<u8> = $fn_name.bytes().chain(once(0)).collect();
            let proc_addr = {
                let handle = LoadLibraryW(PCWSTR::from_raw(dll_name_u16.as_ptr()))?;
                GetProcAddress(handle, PCSTR::from_raw(fn_name_u8.as_ptr()))
                    .ok_or("No function found")?
            };

            let orig: $fn_type = mem::transmute(proc_addr);
            let hooked_fn = GenericDetour::new(orig, $new_fn)?;
            hooked_fn.enable()?;
            Ok(hooked_fn)
        })()
    };
}

// DLL entry point, called by the injector
#[no_mangle]
extern "system" fn init() {
    run_init().unwrap_window();
}

fn run_init() -> Result<(), Box<dyn Error>> {
    if let Some(dir) = get_base_dir("pso2.exe")? {
        *PATH.write() = Some(PathBuf::from(dir));
    } else {
        // fallback to PWD
        *PATH.write() = Some(PathBuf::new());
    }

    if !check_ngs() {
        process_manip::print_msgbox(
            "This DLL is meant for the NGS version of the game",
            "Invalid version",
        );
        return Ok(());
    }

    *SETTINGS.write() = Some(read_settings());
    let settings_lock = SETTINGS.read();
    let settings = settings_lock.as_ref().unwrap_window();
    if !settings.user_key.is_empty() {
        let key_path = std::path::PathBuf::from(&settings.user_key);
        let key_path = if key_path.is_absolute() {
            key_path
        } else {
            PATH.read().as_ref().unwrap_window().join(key_path)
        };
        if let Ok(mut x) = File::open(&key_path) {
            x.read_to_end(USER_RSA_KEY.write().as_mut())?;
        }
    }
    if !settings.user_key.is_empty() || settings.auto_key_fetch {
        // SAFETY: `crypt_open_stub` signature matches the actual function
        unsafe {
            *HOOK_CRYPT_OPEN.write() = Some(create_hook!(
                    "advapi32.dll", "CryptImportKey" =>
                    crypt_open_stub: CryptImportKeyFn
            )?);
        }
    }
    if settings.replace_address {
        // SAFETY: `getaddrinfo_stub` signature matches the actual function
        unsafe {
            *HOOK_GETADDRINFO.write() = Some(create_hook!(
                    "Ws2_32.dll", "getaddrinfo" =>
                    getaddrinfo_stub: GetaddrinfoFn
            )?);
        }
        if settings.auto_key_fetch {
            // SAFETY: `connect_stub` signature matches the actual function
            unsafe {
                *HOOK_CONNECT.write() = Some(create_hook!(
                    "Ws2_32.dll", "connect" =>
                    connect_stub: ConnectFn
                )?);
            }
        }
    }
    Ok(())
}

fn read_settings() -> Settings {
    let path = PATH.read().as_ref().unwrap_window().join("config.toml");
    let mut file = match File::options().read(true).open(&path) {
        Ok(f) => f,
        Err(e) => {
            process_manip::print_msgbox(
                &format!("Failed to open settings file: {e}, creating default file"),
                "Read settings failed",
            );
            let set = Default::default();
            let mut file = File::options()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&path)
                .unwrap_window();
            file.write_all(toml::to_string(&set).unwrap_window().as_bytes())
                .unwrap_window();
            return set;
        }
    };
    let mut toml_string = String::new();
    file.read_to_string(&mut toml_string).unwrap_window();

    match toml::from_str(&toml_string) {
        Ok(s) => s,
        Err(e) => {
            process_manip::print_msgbox(
                &format!("Failed to parse settings file: {e}, using defaults"),
                "Read settings failed",
            );
            Default::default()
        }
    }
}

/// Replaces the original RSA key
///
/// Stubs `CryptImportKey`
extern "system" fn crypt_open_stub(
    hprov: usize,
    pbdata: *const u8,
    dwdatalen: u32,
    hpubkey: usize,
    dwflags: CRYPT_KEY_FLAGS,
    phkey: *mut usize,
) -> bool {
    if pbdata.is_null() || dwdatalen == 0 {
        let hook_lock = HOOK_CRYPT_OPEN.read();
        return hook_lock
            .as_ref()
            .unwrap()
            .call(hprov, pbdata, dwdatalen, hpubkey, dwflags, phkey);
    }
    let user_key = USER_RSA_KEY.read();
    let mut data_location = (pbdata, dwdatalen);
    if !user_key.is_empty() {
        // SAFETY: 1) pbdata is not nullptr
        // 2) here we work with bytes, so they are alligned
        // 3) pbdata must point to a valid PUBLICKEYSTRUC blob
        let orig_key = unsafe { slice::from_raw_parts(pbdata, dwdatalen as usize) };
        {
            let mut keys = SEGA_RSA_KEYS.write();
            if keys.len() == 0 {
                if let Some(x) = get_rsa_key().unwrap_window() {
                    *keys = x;
                }
            };
        }
        for key in SEGA_RSA_KEYS.read().iter() {
            if key.len() != dwdatalen as usize || orig_key != key {
                continue;
            }
            data_location.0 = user_key.as_ptr();
            data_location.1 = user_key.len() as u32;
            break;
        }
    }

    let hook_lock = HOOK_CRYPT_OPEN.read();
    hook_lock.as_ref().unwrap().call(
        hprov,
        data_location.0,
        data_location.1,
        hpubkey,
        dwflags,
        phkey,
    )
}

/// Address replacement
///
/// Stubs `getaddrinfo`
extern "system" fn getaddrinfo_stub(
    pnodename: PCSTR,
    pservicename: PCSTR,
    phints: *const ADDRINFOA,
    ppresult: *mut *mut ADDRINFOA,
) -> i32 {
    if pnodename.is_null() {
        let hook_lock = HOOK_GETADDRINFO.read();
        return hook_lock
            .as_ref()
            .unwrap()
            .call(pnodename, pservicename, phints, ppresult);
    }

    let settings_lock = SETTINGS.read();
    let settings = settings_lock.as_ref().unwrap_window();
    //SAFETY: 1) pnodename is not null
    //2) pnodename should be valid up to and including a `\0` byte
    let mut addr_in = unsafe { pnodename.to_string().unwrap_window() };
    let mut is_changed = false;
    for addr in &settings.addresses {
        if addr_in.contains(&addr.old) {
            addr_in = addr.new.clone();
            is_changed = true;
            break;
        }
    }
    if settings.auto_key_fetch && is_changed {
        // auto key negotiation
        if let Ok(mut socket) = TcpStream::connect((addr_in.as_str(), 11000)) {
            // read structure len
            let mut len = [0u8; 4];
            socket.read_exact(&mut len).unwrap_window();
            let len = u32::from_le_bytes(len);

            // read serialized keys
            let mut data = vec![0u8; len as usize];
            socket.read_exact(&mut data).unwrap_window();
            let keys = match rmp_serde::from_slice::<Vec<Keys>>(&data) {
                Ok(k) => k,
                Err(e) => {
                    process_manip::print_msgbox(
                        &format!("Failed to parse keys: {e}"),
                        "Key negotiation failed",
                    );
                    Default::default()
                }
            };

            *SHIP_RSA_KEYS.write() = keys;
        }
    }
    let addr_in = CString::new(addr_in).unwrap_window();
    let hook_lock = HOOK_GETADDRINFO.read();
    hook_lock.as_ref().unwrap().call(
        // SAFETY: addr_in will live to the end of this function
        PCSTR::from_raw(addr_in.as_ptr() as *const u8),
        pservicename,
        phints,
        ppresult,
    )
}

/// Replaces the user key with auto negotiated key
///
/// Stubs: `connect`
extern "system" fn connect_stub(s: SOCKET, name: *const SOCKADDR, namelen: i32) -> i32 {
    if name.is_null() {
        let hook_lock = HOOK_CONNECT.read();
        return hook_lock.as_ref().unwrap().call(s, name, namelen);
    }
    // SAFETY: 1) name is not null
    // 2) due to connect contract name must point to a valid SOCKADDR
    let name_deref = unsafe { &*name };
    if name_deref.sa_family == AF_INET {
        // SAFETY: because the family is IPv4 we can safely interpret SOCKADDR as SOCKADDR_IN
        let name_deref = unsafe { &*(name as *const SOCKADDR_IN) };

        // get IP as bytes
        //
        // SAFETY: accessing the byte variant of the union is safe because
        // 1) all variants have the same size
        // 2) u8 repr is valia for all u32 reprs
        let ip = unsafe { name_deref.sin_addr.S_un.S_un_b };
        let ip = Ipv4Addr::new(ip.s_b1, ip.s_b2, ip.s_b3, ip.s_b4);
        let lock = SHIP_RSA_KEYS.read();
        let key = lock.iter().find(|ship| ship.ip == ip);
        if let Some(key) = key {
            *USER_RSA_KEY.write() = key.key.clone();
        }
    }
    let hook_lock = HOOK_CONNECT.read();
    hook_lock.as_ref().unwrap().call(s, name, namelen)
}

fn get_rsa_key() -> Result<Option<Vec<Vec<u8>>>, windows::core::Error> {
    let settings_lock = SETTINGS.read();
    let settings = settings_lock.as_ref().unwrap_window();
    let pid = get_process_pid("pso2.exe")?.unwrap_window();
    let Some(data) = get_module_mem(pid, "pso2reboot.dll")? else {
        return Ok(None);
    };
    let mut keys: Vec<Vec<u8>> = vec![];
    let mut data_iter = data.iter();
    let mut key_num = 1;
    while data_iter.any(|&x| x == RSAHEADER[0]) {
        let tmp_iter = data_iter.by_ref().take(RSAHEADER.len() - 1);
        if tmp_iter
            .zip(RSAHEADER.into_iter().skip(1))
            .filter(|x| *x.0 == x.1)
            .count()
            == (RSAHEADER.len() - 1)
        {
            // https://learn.microsoft.com/en-us/windows/win32/seccrypto/enhanced-provider-key-blobs
            // rsapubkey.bitlen as [u8; 4]
            let key_bit_len_buff: Vec<u8> = data_iter.by_ref().take(4).copied().collect();
            // rsapubkey.bitlen as u32 / 8
            let key_len =
                u32::from_le_bytes(key_bit_len_buff.clone().try_into().unwrap_window()) / 8;
            let key: Vec<u8> = RSAHEADER
                .into_iter()
                .chain(key_bit_len_buff)
                .chain(
                    data_iter
                        .by_ref()
                        // + 4 is rsapubkey.pubexp
                        .take(key_len as usize + 4)
                        .copied(),
                )
                .collect();
            if settings.grab_keys {
                let path = PATH
                    .read()
                    .as_ref()
                    .unwrap_window()
                    .join(format!("SEGAKey{key_num}.blob"));
                std::fs::write(path, &key).unwrap_window();
            }
            key_num += 1;
            keys.push(key);
        }
    }

    Ok(Some(keys))
}

fn get_base_dir(process_name: &str) -> Result<Option<String>, windows::core::Error> {
    let Some(pid) = get_process_pid(process_name)? else {
        return Ok(None);
    };
    let modules = ModuleSnapshot::new(pid)?;
    for module in modules {
        let module = module?;
        if module.module_name == process_name {
            let exe_path = std::path::PathBuf::from(module.module_path);
            let dir = exe_path
                .parent()
                .unwrap_window()
                .to_string_lossy()
                .to_string();
            return Ok(Some(dir));
        }
    }
    Ok(None)
}

fn get_process_pid(process_name: &str) -> Result<Option<u32>, windows::core::Error> {
    let processes = ProcessSnapshot::new()?;
    for process in processes {
        let process = process?;
        if process.process_name == process_name {
            return Ok(Some(process.pid));
        }
    }
    Ok(None)
}

fn get_module_mem(pid: u32, module_name: &str) -> Result<Option<&[u8]>, windows::core::Error> {
    let modules = ModuleSnapshot::new(pid)?;
    for module in modules {
        let module = module?;
        if module.module_name == module_name {
            return Ok(Some(unsafe { module.get_memory() }));
        }
    }
    Ok(None)
}

fn check_ngs() -> bool {
    let mut path = PATH.read().clone().unwrap_window();
    match fs::metadata(path.join("pso2_bin")) {
        Ok(x) if x.is_dir() => path.push("pso2_bin"),
        Ok(_) | Err(_) => {}
    };
    path.push("pso2reboot.dll");
    if fs::metadata(path).is_ok() {
        return true;
    }
    false
}
