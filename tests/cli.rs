use std::process::Command;

#[test]
fn node_exits_successfully_without_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_ravel"))
        .arg("node")
        .output()
        .expect("ravel binary should run");

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn invalid_subcommand_prints_usage_and_exits_two() {
    let output = Command::new(env!("CARGO_BIN_EXE_ravel"))
        .arg("bogus")
        .output()
        .expect("ravel binary should run");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"Usage: ravel node\n");
}
