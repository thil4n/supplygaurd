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

const INSTALL_SCRIPTS: [&str; 3] = ["preinstall", "install", "postinstall"];

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
