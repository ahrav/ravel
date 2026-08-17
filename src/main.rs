use std::{ffi::OsStr, path::PathBuf, process::ExitCode};

use ravel::sandbox::{
    HostIsolation, PreflightBehavior, PreflightRoots, UnsupportedHost, preflight,
    preflight_behavior,
};

/// Keeps namespace entry ahead of thread or async-runtime construction. commentlint: allow(JUDGE)
fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);

    match args.next() {
        Some(command) if command == OsStr::new("node") && args.next().is_none() => {
            ExitCode::SUCCESS
        }
        Some(command) if command == OsStr::new("sandbox-preflight") => {
            let (Some(toolchain_root), Some(workspace_root), None) =
                (args.next(), args.next(), args.next())
            else {
                eprintln!("Usage: ravel sandbox-preflight <toolchain_root> <workspace_root>");
                return ExitCode::from(2);
            };
            let roots = match PreflightRoots::new(
                PathBuf::from(toolchain_root),
                PathBuf::from(workspace_root),
            ) {
                Ok(roots) => roots,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::from(error.code());
                }
            };
            let isolation = match HostIsolation::enter() {
                Ok(isolation) => isolation,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::from(error.code());
                }
            };
            match preflight(&isolation, &roots) {
                Ok(receipt) => {
                    println!("{receipt}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::from(error.code())
                }
            }
        }
        Some(command) if command == OsStr::new("sandbox-behavioral-preflight") => {
            let (Some(check), Some(toolchain_root), Some(workspace_root), None) =
                (args.next(), args.next(), args.next(), args.next())
            else {
                eprintln!(
                    "Usage: ravel sandbox-behavioral-preflight <check> <toolchain_root> <workspace_root>"
                );
                return ExitCode::from(2);
            };
            let check = match check.to_str() {
                Some("environment-and-mounts") => PreflightBehavior::EnvironmentAndMounts,
                Some("network-and-host-paths") => PreflightBehavior::NetworkAndHostPaths,
                Some("overlay-cap-tamper") => PreflightBehavior::OverlayCapTamper,
                Some("termination-reap") => PreflightBehavior::TerminationReap,
                Some("overlay-lifecycle") => PreflightBehavior::OverlayLifecycle,
                Some("overlay-freshness-cargo") => PreflightBehavior::OverlayFreshnessCargo,
                _ => {
                    let error = UnsupportedHost::UnknownBehavior;
                    eprintln!("{error}");
                    return ExitCode::from(error.code());
                }
            };
            let isolation = match HostIsolation::enter() {
                Ok(isolation) => isolation,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::from(error.code());
                }
            };
            let roots = match PreflightRoots::new(
                PathBuf::from(toolchain_root),
                PathBuf::from(workspace_root),
            ) {
                Ok(roots) => roots,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::from(error.code());
                }
            };
            match preflight_behavior(&isolation, &roots, check) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::from(error.code())
                }
            }
        }
        _ => {
            eprintln!("Usage: ravel node");
            ExitCode::from(2)
        }
    }
}
