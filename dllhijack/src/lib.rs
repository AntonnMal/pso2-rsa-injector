use windows::{
    core::{PCSTR, PCWSTR},
    Win32::{
        Foundation::{/* GetLastError, */ BOOL, HINSTANCE, HWND},
        System::{
            LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW},
            // SystemInformation::GetSystemDirectoryW,
            SystemServices::DLL_PROCESS_ATTACH,
        },
        UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK},
    },
};
#[no_mangle]
extern "system" fn DllMain(_: HINSTANCE, fdw_reason: u32, _: *mut ()) -> BOOL {
    if fdw_reason == DLL_PROCESS_ATTACH {
        // let mut win_dir = vec![0; 1024];
        // let win_dir_len = unsafe { GetSystemDirectoryW(Some(&mut win_dir)) } as usize;
        // if win_dir_len == 0 {
        //     print_msgbox(
        //         &format!("{:?}", unsafe { GetLastError() }),
        //         "GetSystemDirectory error",
        //     );
        //     return false.into();
        // }
        // let mut dll_name = String::from_utf16_lossy(&win_dir[0..win_dir_len]);
        // dll_name.push_str("\\cryptbase.dll");
        let dll_name = "rsa_inject.dll";
        let cryptbase_path: Vec<_> = dll_name.encode_utf16().chain([0]).collect();
        if let Ok(_) = unsafe { GetModuleHandleW(PCWSTR::from_raw(cryptbase_path.as_ptr())) } {
            return false.into();
        }
        // UNSAFETY: Calling LoadLibrary in DllMain is prohibited.
        let module = match unsafe { LoadLibraryW(PCWSTR::from_raw(cryptbase_path.as_ptr())) } {
            Ok(m) => m,
            Err(e) => {
                print_msgbox(&format!("{e}"), "LoadLibrary error");
                return false.into();
            }
        };
        let init_str = "init\0";
        let init_fn = unsafe { GetProcAddress(module, PCSTR::from_raw(init_str.as_ptr())) };
        // UNSAFETY: Synchronization is prohibited. (I think mutexes count)
        match init_fn {
            Some(f) => unsafe { std::mem::transmute::<_, extern "system" fn()>(f)() },
            None => {}
        };
    }
    false.into()
}

fn print_msgbox(msg: &str, header: &str) {
    let msg_utf16: Vec<_> = msg.encode_utf16().chain([0]).collect();
    let header_utf16: Vec<_> = header.encode_utf16().chain([0]).collect();
    unsafe {
        MessageBoxW(
            HWND::default(),
            PCWSTR::from_raw(msg_utf16.as_ptr()),
            PCWSTR::from_raw(header_utf16.as_ptr()),
            MB_OK | MB_ICONERROR,
        )
    };
}
