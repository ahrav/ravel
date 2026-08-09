use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ravel"))
        .args(args)
        .env_clear()
        .output()
        .expect("ravel binary should run")
}

#[test]
fn node_exits_successfully_without_output() {
    let output = run(&["node"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn invalid_argv_prints_usage_and_exits_two() {
    for argv in [
        &[][..],
        &["bogus"][..],
        &["node", "extra"][..],
        &["--help"][..],
    ] {
        let output = run(argv);

        assert_eq!(output.status.code(), Some(2), "argv {argv:?}");
        assert!(output.stdout.is_empty(), "argv {argv:?}");
        assert_eq!(output.stderr, b"Usage: ravel node\n", "argv {argv:?}");
    }
}
