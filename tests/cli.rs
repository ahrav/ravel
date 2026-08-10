use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ravel"))
        .args(args)
        .env_clear()
        // env_clear() would drop CI's ambient-AWS guards, so the child re-declares
        // them: a default-startup regression that initializes AWS config must not be
        // able to reach IMDS or on-disk credentials from inside this smoke test.
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .env("AWS_CONFIG_FILE", "/dev/null")
        .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
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
