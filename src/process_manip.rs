use std::{mem::size_of, slice};

use libloading::{Library, Symbol};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, HANDLE, HWND},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW,
                Process32NextW, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE,
                TH32CS_SNAPPROCESS,
            },
            Threading::{OpenProcess, PROCESS_ALL_ACCESS},
        },
        UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK},
    },
};

pub struct ProcessEntry {
    pub pid: u32,
    pub threads: u32,
    pub parrent_pid: u32,
    pub base_priority: i32,
    pub process_name: String,
}

pub struct ProcessSnapshot {
    snapshot_handle: HANDLE,
    winapi_module_entry: PROCESSENTRY32W,
    is_first: bool,
    is_empty: bool,
}

pub struct ModuleEntry {
    module_addr: *mut u8,
    module_size: u32,
    pub module_name: String,
    pub module_path: String,
}

pub struct ModuleSnapshot {
    snapshot_handle: HANDLE,
    winapi_module_entry: MODULEENTRY32W,
    is_first: bool,
    is_empty: bool,
}

impl ProcessSnapshot {
    pub fn new() -> Result<Self, windows::core::Error> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;
        let process_entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        Ok(Self {
            snapshot_handle: snapshot,
            winapi_module_entry: process_entry,
            is_first: true,
            is_empty: false,
        })
    }

    pub fn next(&mut self) -> Option<ProcessEntry> {
        if self.is_empty {
            return None;
        }
        if self.is_first {
            self.is_first = false;
            if unsafe {
                Process32FirstW(
                    self.snapshot_handle,
                    std::ptr::addr_of_mut!(self.winapi_module_entry),
                )
            }
            .is_err()
            {
                self.is_empty = true;
                return None;
            };
        } else {
            if unsafe {
                Process32NextW(
                    self.snapshot_handle,
                    std::ptr::addr_of_mut!(self.winapi_module_entry),
                )
            }
            .is_err()
            {
                self.is_empty = true;
                return None;
            };
        }
        let mut process_name = match String::from_utf16(&self.winapi_module_entry.szExeFile) {
            Ok(x) => x,
            Err(_) => "".to_string(),
        };
        process_name.retain(|x| x != '\0');
        self.winapi_module_entry.szExeFile.fill(0);
        Some(ProcessEntry {
            pid: self.winapi_module_entry.th32ProcessID,
            threads: self.winapi_module_entry.cntThreads,
            parrent_pid: self.winapi_module_entry.th32ParentProcessID,
            base_priority: self.winapi_module_entry.pcPriClassBase,
            process_name,
        })
    }
}

impl ModuleSnapshot {
    pub fn new(pid: u32) -> Result<Self, windows::core::Error> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid) }?;
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

    pub fn next(&mut self) -> Option<ModuleEntry> {
        if self.is_empty {
            return None;
        }
        if self.is_first {
            self.is_first = false;
            if unsafe {
                Module32FirstW(
                    self.snapshot_handle,
                    std::ptr::addr_of_mut!(self.winapi_module_entry),
                )
            }
            .is_err()
            {
                self.is_empty = true;
                return None;
            };
        } else {
            if unsafe {
                Module32NextW(
                    self.snapshot_handle,
                    std::ptr::addr_of_mut!(self.winapi_module_entry),
                )
            }
            .is_err()
            {
                self.is_empty = true;
                return None;
            };
        }
        let mut module_name = match String::from_utf16(&self.winapi_module_entry.szModule) {
            Ok(x) => x,
            Err(_) => "".to_string(),
        };
        module_name.retain(|x| x != '\0');
        self.winapi_module_entry.szModule.fill(0);
        let mut module_path = match String::from_utf16(&self.winapi_module_entry.szExePath) {
            Ok(x) => x,
            Err(_) => "".to_string(),
        };
        module_path.retain(|x| x != '\0');
        self.winapi_module_entry.szExePath.fill(0);
        Some(ModuleEntry {
            module_addr: self.winapi_module_entry.modBaseAddr,
            module_size: self.winapi_module_entry.modBaseSize,
            module_name,
            module_path,
        })
    }
}

impl Iterator for ModuleSnapshot {
    type Item = ModuleEntry;

    fn next(&mut self) -> Option<Self::Item> {
        self.next()
    }
}

impl Iterator for ProcessSnapshot {
    type Item = ProcessEntry;

    fn next(&mut self) -> Option<Self::Item> {
        self.next()
    }
}

impl Drop for ModuleSnapshot {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.snapshot_handle) };
    }
}

impl Drop for ProcessSnapshot {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.snapshot_handle) };
    }
}

impl ModuleEntry {
    pub unsafe fn get_memory(&self) -> &'static [u8] {
        slice::from_raw_parts(self.module_addr, self.module_size as usize)
    }
}

pub fn print_msgbox(msg: &str, header: &str) {
    let msg_u16_str: Vec<u16> = msg.encode_utf16().chain(0..=0).collect();
    let header_u16_str: Vec<u16> = header.encode_utf16().chain(0..=0).collect();
    unsafe {
        MessageBoxW(
            HWND::default(),
            PCWSTR::from_raw(msg_u16_str.as_ptr()),
            PCWSTR::from_raw(header_u16_str.as_ptr()),
            MB_OK | MB_ICONERROR,
        )
    };
}

pub fn suspend_process(process_id: u32) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        let lib = Library::new("ntdll.dll")?;
        let nt_suspend_process: Symbol<unsafe extern "C" fn(HANDLE) -> u32> =
            lib.get(b"NtSuspendProcess")?;
        let handle = OpenProcess(PROCESS_ALL_ACCESS, false, process_id)?;
        nt_suspend_process(handle);
        CloseHandle(handle)?;
    }
    Ok(())
}

pub fn resume_process(process_id: u32) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        let lib = Library::new("ntdll.dll")?;
        let nt_resume_process: Symbol<unsafe extern "C" fn(HANDLE) -> u32> =
            lib.get(b"NtResumeProcess")?;
        let handle = OpenProcess(PROCESS_ALL_ACCESS, false, process_id)?;
        nt_resume_process(handle);
        CloseHandle(handle)?;
    }
    Ok(())
}

pub trait PrintWindowResult<T, E> {
    fn unwrap_window(self) -> T
    where
        E: std::fmt::Debug;
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

pub trait PrintWindowOption<T> {
    fn unwrap_window(self) -> T;
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
