pub(crate) mod process_manip;
use core::slice;
use detour::{Function, GenericDetour};
use process_manip::{ModuleSnapshot, PrintWindowOption, PrintWindowResult, ProcessSnapshot};
use std::{
    error::Error,
    fs::{self, File},
    io::{self, Read, Write},
    mem,
    path::PathBuf,
    sync::Mutex,
};
use windows::{
    core::{PCSTR, PCWSTR},
    Win32::{
        Foundation::{FARPROC, HMODULE, NTSTATUS},
        Security::Cryptography::{
            BCRYPT_ALG_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, CRYPT_KEY_FLAGS,
        },
        System::LibraryLoader::{
            GetModuleHandleExW, GetProcAddress, GET_MODULE_HANDLE_EX_FLAG_PIN,
        },
    },
};

// #[no_mangle]
// extern "system" fn DllMain(_hinstDLL: HINSTANCE, _fdwReason: u32, _lpvReserved: usize) -> bool {
//     print_msgbox("hi", "dllmain");
//     true
// }

// static one_time: Mutex<bool> = Mutex::new(false);

// #[ctor::ctor]
// fn test() {
//     // unsafe {
//     //     SetTimer(HWND::default(), 0, 0, Some(test_timer))
//     // };
//     print_msgbox("hi", "ctor");
// }

// extern "system" fn test_timer(_par1: HWND, _par2: u32, _par3: usize, _par4: u32) {
//     let mut one_time_data = one_time.lock().unwrap();
//     if !*one_time_data {
//         *one_time_data = true;
//         print_msgbox("timer", "from timer")
//     }
// }

static RSAHEADER: [u8; 12] = [
    0x06, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x31,
];

static SEGARSAKEYS: Mutex<Vec<Vec<u8>>> = Mutex::new(vec![]);
static USERRSAKEYS: Mutex<Vec<u8>> = Mutex::new(vec![]);

static HOOK_OPEN: Mutex<Option<GenericDetour<OpenAlgorithmProviderFn>>> = Mutex::new(None);
static HOOK_CRYPT_OPEN: Mutex<Option<GenericDetour<CryptImportKeyFn>>> = Mutex::new(None);

type OpenAlgorithmProviderFn = extern "system" fn(
    *mut BCRYPT_ALG_HANDLE,
    PCWSTR,
    PCWSTR,
    BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
) -> NTSTATUS;

type CryptImportKeyFn =
    extern "system" fn(usize, *const u8, u32, usize, CRYPT_KEY_FLAGS, *mut usize) -> bool;

#[no_mangle]
extern "system" fn init() {
    run_init().unwrap_window();
}

fn run_init() -> Result<(), Box<dyn Error>> {
    unsafe {
        if let Ok(mut x) = File::open("publicKey.blob") {
            x.read_to_end(USERRSAKEYS.lock()?.as_mut())?;
        }
        let orig_import: CryptImportKeyFn =
            mem::transmute(load_fn("cryptsp.dll", "CryptImportKey")?.unwrap_window());
        *HOOK_CRYPT_OPEN.lock()? = Some(create_hook(orig_import, crypt_open_stub)?);
        match get_rsa_key()? {
            Some(x) => *SEGARSAKEYS.lock()? = x,
            None => {
                let orig_import: OpenAlgorithmProviderFn = mem::transmute(
                    load_fn("bcrypt.dll", "BCryptOpenAlgorithmProvider")?.unwrap_window(),
                );
                *HOOK_OPEN.lock()? = Some(create_hook(orig_import, open_stub)?);
            }
        }
    }
    Ok(())
}

extern "system" fn crypt_open_stub(
    hprov: usize,
    pbdata: *const u8,
    dwdatalen: u32,
    hpubkey: usize,
    dwflags: CRYPT_KEY_FLAGS,
    phkey: *mut usize,
) -> bool {
    let user_key = USERRSAKEYS.lock().unwrap_window();
    let mut data_location = (pbdata, dwdatalen);
    let orig_key = unsafe { slice::from_raw_parts_mut(pbdata as *mut u8, dwdatalen as usize) };
    if user_key.len() != 0 {
        for key in SEGARSAKEYS.lock().unwrap_window().iter() {
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

    let hook_lock = HOOK_CRYPT_OPEN.lock().unwrap_window();
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
    let mut keys = SEGARSAKEYS.lock().unwrap_window();
    if keys.len() == 0 {
        if let Some(x) = get_rsa_key().unwrap_window() {
            *keys = x;
        }
    };
    let hook_lock = HOOK_OPEN.lock().unwrap_window();
    hook_lock
        .as_ref()
        .unwrap()
        .call(phalgorithm, pszalgid, pszimplementation, dwflags)
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
            File::create(format!("SEGAKey{key_num}.blob"))
                .unwrap_window()
                .write_all(&key)
                .unwrap_window();
            key_num += 1;
            keys.push(key.into_iter().collect());
        }
    }

    Ok(Some(keys))
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
    let mut path = PathBuf::new();
    match fs::metadata("pso2_bin") {
        Ok(x) if x.is_dir() => path.push("pso2_bin"),
        Ok(_) | Err(_) => {}
    };
    path.push("pso2reboot.dll");
    if fs::metadata(path).is_ok() {
        return true;
    }
    false
}
