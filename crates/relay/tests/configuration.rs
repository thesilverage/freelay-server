use std::process::{Command, Output};

const EXAMPLE: &str = include_str!("../../../freelay.example.toml");

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_freelay"))
        .env_clear()
        .args(args)
        .output()
        .unwrap()
}

fn validate(contents: &str) -> Output {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("freelay.toml");
    std::fs::write(&path, contents).unwrap();
    cli(&["config", "validate", "--config", path.to_str().unwrap()])
}

#[test]
fn required_control_config_rejects_obsolete_and_unsafe_settings() {
    assert!(validate(EXAMPLE).status.success());
    for (contents, message) in [
        (EXAMPLE.replace("[control]", "[freelay]"), "control"),
        (
            EXAMPLE.replace("url = \"http://127.0.0.1:8080/\"\n", ""),
            "[server].url",
        ),
        (
            EXAMPLE.replace(
                "[control]",
                "[control]\npublic_base_url = \"https://old.example/\"",
            ),
            "public_base_url",
        ),
        (
            EXAMPLE.replace("[control]", "[control]\npresigned_url_ttl_seconds = 900"),
            "presigned_url_ttl_seconds",
        ),
        (
            EXAMPLE.replace("type = \"filesystem\"", "type = \"memory\""),
            "persistent store",
        ),
        (
            format!("{EXAMPLE}\n[[auth]]\nprivate_key = \"test-only\"\n"),
            "remove [[auth]]",
        ),
        (
            format!("{EXAMPLE}\n[[webhooks]]\nurl = \"https://example.test/\"\n"),
            "webhooks",
        ),
        (
            EXAMPLE.replace("token_ttl_seconds = 900", "token_ttl_seconds = 0"),
            "TTL",
        ),
    ] {
        let output = validate(&contents);
        assert!(!output.status.success(), "unexpected success: {message}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(message),
            "{:?}",
            output
        );
    }
}

#[test]
fn removed_cli_modes_are_not_accepted() {
    for args in [
        vec!["serve", "--legacy"],
        vec!["serve", "--auth", "test-only"],
        vec!["gen-auth"],
        vec!["sign", "--auth", "test-only"],
        vec!["verify", "--auth", "test-only"],
    ] {
        assert!(!cli(&args).status.success(), "unexpected success: {args:?}");
    }
}

#[test]
fn displayed_config_includes_control_and_uses_only_freelay_overrides() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("freelay.toml");
    std::fs::write(&path, EXAMPLE).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_freelay"));
    command
        .env_clear()
        .args(["config", "show", "--config", path.to_str().unwrap()]);
    command.env("RELAY_SERVER_URL", "https://obsolete.example/");
    let output = command.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("[control]"));
    assert!(text.contains("url = \"http://127.0.0.1:8080/\""));
    command.env("FREELAY_SERVER_URL", "https://current.example/");
    let output = command.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("url = \"https://current.example/\""));
}
