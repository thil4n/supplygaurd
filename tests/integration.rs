use std::process::Command;

fn run_supplygaurd(arg: &str) -> (String, String, bool) {
    let output = Command::new(env!("CARGO_BIN_EXE_supplygaurd"))
        .arg(arg)
        .output()
        .expect("failed to run supplygaurd binary");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();
    (stdout, stderr, success)
}

#[test]
fn test_malicious_package_flagged() {
    let (stdout, _, _) = run_supplygaurd("datasets/malicious/package.json");
    assert!(
        stdout.contains("SUSPICIOUS") || stdout.contains("BLOCK"),
        "expected SUSPICIOUS or BLOCK, got:\n{}",
        stdout
    );
}

#[test]
fn test_benign_package_passes() {
    let (stdout, _, _) = run_supplygaurd("datasets/benign/package.json");
    assert!(
        stdout.contains("PASS"),
        "expected PASS, got:\n{}",
        stdout
    );
}

#[test]
fn test_malicious_contains_threat_indicators() {
    let (stdout, _, _) = run_supplygaurd("datasets/malicious/package.json");
    // The report should call out the specific threat categories present
    assert!(
        stdout.contains("Network") || stdout.contains("Exfiltration") || stdout.contains("Execution"),
        "expected threat indicators in output:\n{}",
        stdout
    );
}

#[test]
fn test_benign_no_install_scripts_message() {
    let (stdout, _, _) = run_supplygaurd("datasets/benign/package.json");
    assert!(
        stdout.contains("No install scripts") || stdout.contains("PASS"),
        "expected no-scripts message:\n{}",
        stdout
    );
}

#[test]
fn test_missing_file_exits_with_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_supplygaurd"))
        .arg("no_such_file_supplygaurd.json")
        .output()
        .expect("failed to run supplygaurd binary");
    assert!(!output.status.success(), "should exit non-zero for missing file");
}

#[test]
fn test_report_includes_package_name() {
    let (stdout, _, _) = run_supplygaurd("datasets/malicious/package.json");
    assert!(
        stdout.contains("totally-legit-utils"),
        "expected package name in report:\n{}",
        stdout
    );
}

#[test]
fn test_report_includes_risk_score() {
    let (stdout, _, _) = run_supplygaurd("datasets/malicious/package.json");
    // Score line looks like "Risk Score: 70/100"
    assert!(
        stdout.contains("/100"),
        "expected risk score in report:\n{}",
        stdout
    );
}
