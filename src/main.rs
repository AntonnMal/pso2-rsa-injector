pub(crate) mod process_manip;
use std::error::Error;
use std::mem;

use dll_syringe::{process::OwnedProcess, Syringe};
use process_manip::{
    resume_process, suspend_process, PrintWindowOption, PrintWindowResult, ProcessSnapshot,
};
fn main() {
    run().unwrap_window();
}

fn run() -> Result<(), Box<dyn Error>> {
    get_process_loop("pso2.exe")?;
    let gg_process = get_process_loop("GameGuard.des")?;
    let process = OwnedProcess::from_pid(get_process_loop("pso2.exe")?)?;
    suspend_process(gg_process)?;
    let syringe = Syringe::for_process(process);
    let injected_payload = loop {
        match syringe.inject("rsa_inject.dll") {
            Ok(x) => break x,
            Err(e) => match e {
                dll_syringe::error::InjectError::ProcessInaccessible => continue,
                _ => Err(e)?,
            },
        };
    };
    let payload_init = unsafe {
        syringe
            .get_raw_procedure::<extern "system" fn()>(injected_payload, "init")?
            .unwrap_window()
    };
    payload_init.call()?;
    mem::forget(syringe);
    resume_process(gg_process)?;
    Ok(())
}

fn get_process_loop(process_name: &str) -> Result<u32, windows::core::Error> {
    loop {
        match get_process(process_name)? {
            Some(x) => break Ok(x),
            None => continue,
        }
    }
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
