use std::process::Command;

fn run_supplygaurd(arg: &str) -> (String, String, bool) {
    let output = Command::new(env!("CARGO_BIN_EXE_supplygaurd"))
        .arg(arg)
        .arg("--offline")
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

// ── Real-world attack samples ─────────────────────────────────────────────────
// Based on publicly documented, already-remediated npm supply chain incidents.

// The following four attacks delegate malicious code to a separate JS file
// (e.g. "node preinstall.js"). SupplyGuard currently only scans the script
// string in package.json, not referenced files. These correctly PASS today —
// closing this gap requires JS file scanning (see roadmap).

#[test]
fn test_ua_parser_js_known_gap() {
    // CVE-2021-41265: payload is in preinstall.js, not in the script string
    let (stdout, _, _) = run_supplygaurd("datasets/malicious/ua-parser-js/package.json");
    assert!(
        stdout.contains("PASS"),
        "ua-parser-js delegates to file — expected PASS (known gap):\n{}",
        stdout
    );
}

#[test]
fn test_crossenv_known_gap() {
    // 2017 typosquat: payload is in lib/post-install.js
    let (stdout, _, _) = run_supplygaurd("datasets/malicious/crossenv/package.json");
    assert!(
        stdout.contains("PASS"),
        "crossenv delegates to file — expected PASS (known gap):\n{}",
        stdout
    );
}

#[test]
fn test_coa_known_gap() {
    // November 2021: payload is in compile.js
    let (stdout, _, _) = run_supplygaurd("datasets/malicious/coa/package.json");
    assert!(
        stdout.contains("PASS"),
        "coa delegates to file — expected PASS (known gap):\n{}",
        stdout
    );
}

#[test]
fn test_eslint_scope_known_gap() {
    // July 2018: payload is in lib/build.js
    let (stdout, _, _) = run_supplygaurd("datasets/malicious/eslint-scope/package.json");
    assert!(
        stdout.contains("PASS"),
        "eslint-scope delegates to file — expected PASS (known gap):\n{}",
        stdout
    );
}

#[test]
fn test_exfil_inline() {
    // Generic pattern seen in dozens of attacks: inline env exfiltration
    let (stdout, _, _) = run_supplygaurd("datasets/malicious/exfil-inline/package.json");
    assert!(
        stdout.contains("SUSPICIOUS") || stdout.contains("BLOCK"),
        "exfil-inline should be flagged:\n{}",
        stdout
    );
    // Should detect multiple threat categories
    assert!(stdout.contains("Network") || stdout.contains("Exfiltration"));
}

#[test]
fn test_reverse_shell() {
    // Common typosquat payload: reverse shell via child_process
    let (stdout, _, _) = run_supplygaurd("datasets/malicious/reverse-shell/package.json");
    assert!(
        stdout.contains("SUSPICIOUS") || stdout.contains("BLOCK"),
        "reverse-shell should be flagged:\n{}",
        stdout
    );
    assert!(stdout.contains("Execution"));
}

#[test]
fn test_dependency_confusion() {
    // Internal package name collision with high version number
    let (stdout, _, _) = run_supplygaurd("datasets/malicious/dependency-confusion/package.json");
    assert!(
        stdout.contains("SUSPICIOUS") || stdout.contains("BLOCK"),
        "dependency-confusion should be flagged:\n{}",
        stdout
    );
}

#[test]
fn test_flatmap_stream_no_install_scripts() {
    // event-stream/flatmap-stream: payload was in source JS, not install scripts
    // SupplyGuard should pass this — it only scans install scripts currently
    let (stdout, _, _) = run_supplygaurd("datasets/malicious/obfuscated-payload/package.json");
    assert!(
        stdout.contains("PASS"),
        "flatmap-stream has no install scripts, should PASS (known gap):\n{}",
        stdout
    );
}

#[test]
fn test_deep_chain_clean_scripts_pass_offline() {
    // No malicious install scripts — clean package used to test recursive scanning.
    // In offline mode (no registry checks), this should PASS.
    let (stdout, _, _) = run_supplygaurd("datasets/malicious/deep-chain/package.json");
    assert!(
        stdout.contains("PASS"),
        "deep-chain has no install scripts, should PASS in offline mode:\n{}",
        stdout
    );
}
