use std::{iter::once, mem::size_of, slice};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, ERROR_NO_MORE_FILES, HANDLE, HWND},
        System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW,
            Process32NextW, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPPROCESS,
        },
        UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK},
    },
};

/// Wrapper type around WinApi process snapshots
pub struct ProcessSnapshot {
    snapshot_handle: HANDLE,
    winapi_process_entry: PROCESSENTRY32W,
    is_first: bool,
    is_empty: bool,
}

/// Wrapper type around WinApi `PROCESSENTRY32W`
///
/// See more: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32w
pub struct ProcessEntry {
    /// Querried process ID
    pub pid: u32,
    /// Querried process EXE name
    pub process_name: String,
}

/// Wrapper type around WinApi module snapshots
pub struct ModuleSnapshot {
    snapshot_handle: HANDLE,
    winapi_module_entry: MODULEENTRY32W,
    is_first: bool,
    is_empty: bool,
}

/// Wrapper type around WinApi `MODULEENTRY32W`
///
/// See more: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-moduleentry32w
pub struct ModuleEntry {
    /// Address of the module in the context of the owning process
    module_addr: *mut u8,
    /// Total module size
    module_size: u32,
    /// Module EXE name
    pub module_name: String,
    /// Path to module EXE
    pub module_path: String,
}

/// Trait for printing `Result::unwrap()` to a message box
pub trait PrintWindowResult<T, E> {
    fn unwrap_window(self) -> T
    where
        E: std::fmt::Debug;
}

/// Trait for printing `Option::unwrap()` to a message box
pub trait PrintWindowOption<T> {
    fn unwrap_window(self) -> T;
}

impl ProcessSnapshot {
    pub fn new() -> Result<Self, windows::core::Error> {
        //SAFETY: this call is safe, because
        //1) this function takes no pointers
        //2) this function should be thread safe
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;
        // as per winapi convention we need to write the structure size
        let process_entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        Ok(Self {
            snapshot_handle: snapshot,
            winapi_process_entry: process_entry,
            is_first: true,
            is_empty: false,
        })
    }

    pub fn next(&mut self) -> Option<Result<ProcessEntry, windows::core::Error>> {
        if self.is_empty {
            return None;
        }
        let proc_entry_ptr = std::ptr::addr_of_mut!(self.winapi_process_entry);
        if self.is_first {
            self.is_first = false;
            //SAFETY: this call is safe, because
            //1) proc_entry_ptr points to a valid instance of PROCESSENTRY32W
            //2) this function should be thread safe
            match unsafe { Process32FirstW(self.snapshot_handle, proc_entry_ptr) } {
                Ok(_) => {}
                Err(e) if e == ERROR_NO_MORE_FILES.into() => {
                    self.is_empty = true;
                    return None;
                }
                Err(e) => return Some(Err(e)),
            }
        } else {
            //SAFETY: see above
            match unsafe { Process32NextW(self.snapshot_handle, proc_entry_ptr) } {
                Ok(_) => {}
                Err(e) if e == ERROR_NO_MORE_FILES.into() => {
                    self.is_empty = true;
                    return None;
                }
                Err(e) => return Some(Err(e)),
            }
        }
        let mut process_name =
            String::from_utf16(&self.winapi_process_entry.szExeFile).unwrap_or_default();

        // remove all null bytes
        process_name.retain(|x| x != '\0');
        // clear process name for next iteration
        self.winapi_process_entry.szExeFile.fill(0);
        Some(Ok(ProcessEntry {
            pid: self.winapi_process_entry.th32ProcessID,
            process_name,
        }))
    }
}

impl ModuleSnapshot {
    pub fn new(pid: u32) -> Result<Self, windows::core::Error> {
        //SAFETY: this call is safe, because
        //1) this function takes no pointers
        //2) this function should be thread safe
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid) }?;
        // as per winapi convention we need to write the structure size
        let module_entry = MODULEENTRY32W {
            dwSize: size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };
        Ok(Self {
            snapshot_handle: snapshot,
            winapi_module_entry: module_entry,
            is_first: true,
            is_empty: false,
        })
    }

    pub fn next(&mut self) -> Option<Result<ModuleEntry, windows::core::Error>> {
        if self.is_empty {
            return None;
        }
        let mod_entry_ptr = std::ptr::addr_of_mut!(self.winapi_module_entry);
        if self.is_first {
            self.is_first = false;
            //SAFETY: this call is safe, because
            //1) mod_entry_ptr points to a valid instance of MODULEENTRY32W
            //2) this function should be thread safe
            match unsafe { Module32FirstW(self.snapshot_handle, mod_entry_ptr) } {
                Ok(_) => {}
                Err(e) if e == ERROR_NO_MORE_FILES.into() => {
                    self.is_empty = true;
                    return None;
                }
                Err(e) => return Some(Err(e)),
            }
        } else {
            //SAFETY: this call is safe, because
            //1) mod_entry_ptr points to a valid instance of MODULEENTRY32W
            //2) this function should be thread safe
            match unsafe { Module32NextW(self.snapshot_handle, mod_entry_ptr) } {
                Ok(_) => {}
                Err(e) if e == ERROR_NO_MORE_FILES.into() => {
                    self.is_empty = true;
                    return None;
                }
                Err(e) => return Some(Err(e)),
            }
        }
        let mut module_name =
            String::from_utf16(&self.winapi_module_entry.szModule).unwrap_or_default();
        let mut module_path =
            String::from_utf16(&self.winapi_module_entry.szExePath).unwrap_or_default();
        // remove all null bytes
        module_name.retain(|x| x != '\0');
        module_path.retain(|x| x != '\0');
        // clear strings for next iteration
        self.winapi_module_entry.szModule.fill(0);
        self.winapi_module_entry.szExePath.fill(0);
        Some(Ok(ModuleEntry {
            module_addr: self.winapi_module_entry.modBaseAddr,
            module_size: self.winapi_module_entry.modBaseSize,
            module_name,
            module_path,
        }))
    }
}

impl ModuleEntry {
    /// Returns a view of module memory
    ///
    /// SAFETY:
    /// 1) module entry must point to valid module
    /// 2) caller must have read access to module memory
    /// 3) memory reference MUST NOT outlive the module lifetime
    pub unsafe fn get_memory(&self) -> &'static [u8] {
        slice::from_raw_parts(self.module_addr, self.module_size as usize)
    }
}

impl Iterator for ProcessSnapshot {
    type Item = Result<ProcessEntry, windows::core::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next()
    }
}

impl Iterator for ModuleSnapshot {
    type Item = Result<ModuleEntry, windows::core::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next()
    }
}

impl Drop for ProcessSnapshot {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.snapshot_handle) };
    }
}

impl Drop for ModuleSnapshot {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.snapshot_handle) };
    }
}

pub fn print_msgbox(msg: &str, header: &str) {
    let msg_u16_str: Vec<u16> = msg.encode_utf16().chain(once(0)).collect();
    let header_u16_str: Vec<u16> = header.encode_utf16().chain(once(0)).collect();
    //SAFETY: message and header pointers point to a valid UTF16 strings
    unsafe {
        MessageBoxW(
            HWND::default(),
            PCWSTR::from_raw(msg_u16_str.as_ptr()),
            PCWSTR::from_raw(header_u16_str.as_ptr()),
            MB_OK | MB_ICONERROR,
        )
    };
}

impl<T, E> PrintWindowResult<T, E> for Result<T, E> {
    #[track_caller]
    fn unwrap_window(self) -> T
    where
        E: std::fmt::Debug,
    {
        match self {
            Ok(val) => val,
            Err(e) => {
                let caller = std::panic::Location::caller();
                print_msgbox(
                    &format!(
                        "Called `Result::unwrap_window()` on an `Err` value: {e:?} in {} at {}",
                        caller.file(),
                        caller.line()
                    ),
                    "Error",
                );
                panic!();
            }
        }
    }
}

impl<T> PrintWindowOption<T> for Option<T> {
    #[track_caller]
    fn unwrap_window(self) -> T {
        match self {
            Some(val) => val,
            None => {
                let caller = std::panic::Location::caller();
                print_msgbox(
                    &format!(
                        "Called `Option::unwrap_window()` on an `None` value in {} at {}",
                        caller.file(),
                        caller.line()
                    ),
                    "Error",
                );
                panic!();
            }
        }
    }
}
