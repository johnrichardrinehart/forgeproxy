use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=FORGEPROXY_GIT_REVISION");
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/refs");

    let revision = std::env::var("FORGEPROXY_GIT_REVISION")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(git_revision)
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=FORGEPROXY_GIT_REVISION={revision}");
}

fn git_revision() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let revision = String::from_utf8(output.stdout).ok()?;
    let revision = revision.trim();
    if revision.is_empty() {
        None
    } else {
        Some(revision.to_string())
    }
}
