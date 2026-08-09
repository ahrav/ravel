use std::{ffi::OsStr, process::ExitCode};

fn main() -> ExitCode {
    let mut args = std::env::args_os();
    let _program = args.next();

    if args.next().as_deref() == Some(OsStr::new("node")) && args.next().is_none() {
        ExitCode::SUCCESS
    } else {
        eprintln!("Usage: ravel node");
        ExitCode::from(2)
    }
}
