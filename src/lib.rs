pub(crate) mod process_manip;
use core::slice;
use detour::{Function, GenericDetour};
use process_manip::{ModuleSnapshot, PrintWindowOption, PrintWindowResult, ProcessSnapshot};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    ffi::CString,
    fs::{self, File},
    io::{self, Read, Write},
    mem,
    path::PathBuf,
    sync::RwLock,
};
use windows::{
    core::{PCSTR, PCWSTR},
    Win32::{
        Foundation::{FARPROC, HMODULE, NTSTATUS},
        Networking::WinSock::ADDRINFOA,
        Security::Cryptography::{
            BCRYPT_ALG_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, CRYPT_KEY_FLAGS,
        },
        System::LibraryLoader::{
            GetModuleHandleExW, GetProcAddress, GET_MODULE_HANDLE_EX_FLAG_PIN,
        },
    },
};

#[derive(Serialize, Deserialize)]
struct Settings {
    user_key: String,
    grab_keys: bool,
    replace_address: bool,
    addresses: Vec<AddrReplace>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            grab_keys: true,
            replace_address: false,
            user_key: "publicKey.blob".to_string(),
            addresses: vec![AddrReplace::default()],
        }
    }
}
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

static RSAHEADER: [u8; 12] = [
    0x06, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x31,
];

static SEGARSAKEYS: RwLock<Vec<Vec<u8>>> = RwLock::new(vec![]);
static USERRSAKEYS: RwLock<Vec<u8>> = RwLock::new(vec![]);
static SETTINGS: RwLock<Option<Settings>> = RwLock::new(None);

static HOOK_OPEN: RwLock<Option<GenericDetour<OpenAlgorithmProviderFn>>> = RwLock::new(None);
static HOOK_CRYPT_OPEN: RwLock<Option<GenericDetour<CryptImportKeyFn>>> = RwLock::new(None);
static HOOK_GETADDRINFO: RwLock<Option<GenericDetour<GetaddrinfoFn>>> = RwLock::new(None);

static PATH: RwLock<Option<std::path::PathBuf>> = RwLock::new(None);

type OpenAlgorithmProviderFn = extern "system" fn(
    *mut BCRYPT_ALG_HANDLE,
    PCWSTR,
    PCWSTR,
    BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
) -> NTSTATUS;

type CryptImportKeyFn =
    extern "system" fn(usize, *const u8, u32, usize, CRYPT_KEY_FLAGS, *mut usize) -> bool;

type GetaddrinfoFn = extern "system" fn(PCSTR, PCSTR, *const ADDRINFOA, *mut *mut ADDRINFOA) -> i32;

#[no_mangle]
extern "system" fn init() {
    run_init().unwrap_window();
}

fn run_init() -> Result<(), Box<dyn Error>> {
    unsafe {
		if let Some(dir) = get_base_dir("pso2.exe")? {
			*PATH.write()? = Some(PathBuf::from(dir));
		} else {
			*PATH.write()? = Some(PathBuf::new());
		}
        *SETTINGS.write()? = Some(read_settings());
        let settings_lock = SETTINGS.read()?;
        let settings = settings_lock.as_ref().unwrap_window();
        if !settings.user_key.is_empty() {
			let key_path = std::path::PathBuf::from(&settings.user_key);
			let key_path = if key_path.is_absolute() {
				key_path
			} else {
				PATH.read()?.as_ref().unwrap_window().join(key_path)
			};
            if let Ok(mut x) = File::open(&key_path) {
                x.read_to_end(USERRSAKEYS.write()?.as_mut())?;
                let orig_import: CryptImportKeyFn =
                    mem::transmute(load_fn("cryptsp.dll", "CryptImportKey")?.unwrap_window());
                *HOOK_CRYPT_OPEN.write()? = Some(create_hook(orig_import, crypt_open_stub)?);
            }
        }
        if settings.replace_address {
            let orig_getaddrinfo: GetaddrinfoFn =
                mem::transmute(load_fn("Ws2_32.dll", "getaddrinfo")?.unwrap_window());
            *HOOK_GETADDRINFO.write()? = Some(create_hook(orig_getaddrinfo, getaddrinfo_stub)?);
        }

        match get_rsa_key()? {
            Some(x) => *SEGARSAKEYS.write()? = x,
            None => {
                let orig_import: OpenAlgorithmProviderFn = mem::transmute(
                    load_fn("bcrypt.dll", "BCryptOpenAlgorithmProvider")?.unwrap_window(),
                );
                *HOOK_OPEN.write()? = Some(create_hook(orig_import, open_stub)?);
            }
        }
    }
    Ok(())
}

fn read_settings() -> Settings {
	let path = PATH.read().unwrap_window().as_ref().unwrap_window().join("config.toml");
    let mut file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .open(&path)
        .unwrap_window();
    let mut toml_string = String::new();
    file.read_to_string(&mut toml_string).unwrap_window();
    let settings: Settings = toml::from_str(&toml_string).unwrap_or_default();
    drop(file);
    let mut file = File::options()
        .truncate(true)
        .write(true)
        .open(&path)
        .unwrap_window();
    file.write_all(toml::to_string(&settings).unwrap_window().as_bytes())
        .unwrap_window();
    settings
}

extern "system" fn crypt_open_stub(
    hprov: usize,
    pbdata: *const u8,
    dwdatalen: u32,
    hpubkey: usize,
    dwflags: CRYPT_KEY_FLAGS,
    phkey: *mut usize,
) -> bool {
    let user_key = USERRSAKEYS.read().unwrap_window();
    let mut data_location = (pbdata, dwdatalen);
    let orig_key = unsafe { slice::from_raw_parts_mut(pbdata as *mut u8, dwdatalen as usize) };
    if user_key.len() != 0 {
        for key in SEGARSAKEYS.read().unwrap_window().iter() {
            if key.len() != dwdatalen as usize {
                continue;
            }
            if orig_key.iter().zip(key.iter()).any(|x| *x.0 != *x.1) {
                continue;
            }
            data_location.0 = user_key.as_ptr();
            data_location.1 = user_key.len() as u32;
            break;
        }
    }

    let hook_lock = HOOK_CRYPT_OPEN.read().unwrap_window();
    hook_lock.as_ref().unwrap().call(
        hprov,
        data_location.0,
        data_location.1,
        hpubkey,
        dwflags,
        phkey,
    )
}

extern "system" fn open_stub(
    phalgorithm: *mut BCRYPT_ALG_HANDLE,
    pszalgid: PCWSTR,
    pszimplementation: PCWSTR,
    dwflags: BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
) -> NTSTATUS {
    let mut keys = SEGARSAKEYS.write().unwrap_window();
    if keys.len() == 0 {
        if let Some(x) = get_rsa_key().unwrap_window() {
            *keys = x;
        }
    };
    let hook_lock = HOOK_OPEN.read().unwrap_window();
    hook_lock
        .as_ref()
        .unwrap()
        .call(phalgorithm, pszalgid, pszimplementation, dwflags)
}

extern "system" fn getaddrinfo_stub(
    pnodename: PCSTR,
    pservicename: PCSTR,
    phints: *const ADDRINFOA,
    ppresult: *mut *mut ADDRINFOA,
) -> i32 {
    let settings_lock = SETTINGS.read().unwrap_window();
    let settings = settings_lock.as_ref().unwrap_window();
    let mut addr_in = unsafe { pnodename.to_string().unwrap_window() };
    for addr in &settings.addresses {
        if addr_in.contains(&addr.old) {
            addr_in = addr.new.to_string();
            break;
        }
    }
    let addr_in = CString::new(addr_in).unwrap_window();
    let hook_lock = HOOK_GETADDRINFO.read().unwrap_window();
    hook_lock.as_ref().unwrap().call(
        PCSTR::from_raw(addr_in.as_ptr() as *const u8),
        pservicename,
        phints,
        ppresult,
    )
}

fn load_fn(dll_name: &str, fn_name: &str) -> Result<FARPROC, io::Error> {
    unsafe {
        let dll_name_u16: Vec<u16> = dll_name.encode_utf16().chain(0..=0).collect();
        let fn_name_u8: Vec<u8> = fn_name.bytes().chain(0..=0).collect();

        let mut handle = HMODULE::default();
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_PIN,
            PCWSTR::from_raw(dll_name_u16.as_ptr()),
            std::ptr::addr_of_mut!(handle),
        )
        .unwrap();
        Ok(GetProcAddress(handle, PCSTR::from_raw(fn_name_u8.as_ptr())))
    }
}

fn create_hook<T: Function>(orig_fn: T, new_fn: T) -> Result<GenericDetour<T>, Box<dyn Error>> {
    unsafe {
        let hooked_fn = GenericDetour::<T>::new(orig_fn, new_fn)?;
        hooked_fn.enable()?;
        Ok(hooked_fn)
    }
}

fn get_rsa_key() -> Result<Option<Vec<Vec<u8>>>, windows::core::Error> {
    let settings_lock = SETTINGS.read().unwrap_window();
    let settings = settings_lock.as_ref().unwrap_window();
    let pid = get_process("pso2.exe")?.unwrap();
    let module = if check_ngs() {
        "pso2reboot.dll"
    } else {
        "pso2.exe"
    };
    let Some(data) = get_module(pid, module)? else {return Ok(None)};
    let mut keys: Vec<Vec<u8>> = vec![];
    let mut data_iter = data.iter();
    let mut key_num = 1;
    while data_iter.any(|&x| x == RSAHEADER[0]) {
        let tmp_iter = data_iter.by_ref().take(11);
        if tmp_iter
            .zip(RSAHEADER.into_iter().skip(1))
            .filter(|x| *x.0 == x.1)
            .count()
            == 11
        {
            //https://learn.microsoft.com/en-us/windows/win32/seccrypto/enhanced-provider-key-blobs
            let key_len_buff: Vec<u8> = data_iter.by_ref().take(4).copied().collect();
            let key_len = u32::from_le_bytes(key_len_buff.clone().try_into().unwrap_window());
            let key: Vec<u8> = RSAHEADER
                .into_iter()
                .chain(key_len_buff)
                .chain(data_iter.by_ref().take((key_len / 8) as usize + 4).copied())
                .collect();
            if settings.grab_keys {
				let path = PATH.read().unwrap_window().as_ref().unwrap_window().join(format!("SEGAKey{key_num}.blob"));
                File::create(path)
                    .unwrap_window()
                    .write_all(&key)
                    .unwrap_window();
            }
            key_num += 1;
            keys.push(key.into_iter().collect());
        }
    }

    Ok(Some(keys))
}

fn get_base_dir(process_name: &str) -> Result<Option<String>, windows::core::Error> {
	let Some(pid) = get_process(process_name)? else { return Ok(None) };
	let modules = ModuleSnapshot::new(pid)?;
	for module in modules {
        if module.module_name == process_name {
			let exe_path = std::path::PathBuf::from(module.module_path);
			let dir = exe_path.parent().unwrap_window().to_string_lossy().to_string();
            return Ok(Some(dir));
        }
    }
	Ok(None)
}

fn get_process(process_name: &str) -> Result<Option<u32>, windows::core::Error> {
    let processes = ProcessSnapshot::new()?;
    for process in processes {
        if process.process_name == process_name {
            return Ok(Some(process.pid));
        }
    }
    Ok(None)
}

fn get_module(pid: u32, module_name: &str) -> Result<Option<&[u8]>, windows::core::Error> {
    let modules = ModuleSnapshot::new(pid)?;
    for module in modules {
        if module.module_name == module_name {
            return Ok(Some(unsafe { module.get_memory() }));
        }
    }
    Ok(None)
}

fn check_ngs() -> bool {
    let mut path = PATH.read().unwrap_window().clone().unwrap_window();
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
