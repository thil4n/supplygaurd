use crate::analyser::threat::ThreatIndicator;
use crate::analyser::AnalysisResult;
use crate::registry::{RegistryFinding, RegistryRisk, RiskLevel};

// ── Verdict ───────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
pub enum Verdict {
    Pass,
    Suspicious,
    /// exit code 1
    Block,
}

impl Verdict {
    fn message(&self) -> &str {
        match self {
            Verdict::Pass => "PASS — No significant threats detected.",
            Verdict::Suspicious => "SUSPICIOUS — Manual review recommended before installing.",
            Verdict::Block => "BLOCK — Do not install this package.",
        }
    }
}

// ── Report ────────────────────────────────────────────────────────────────────

pub struct Report {
    pub file_path: String,
    pub analysis: AnalysisResult,
    pub registry_risks: Vec<RegistryRisk>,
}

impl Report {
    pub fn new(
        file_path: impl Into<String>,
        analysis: AnalysisResult,
        registry_risks: Vec<RegistryRisk>,
    ) -> Self {
        Self {
            file_path: file_path.into(),
            analysis,
            registry_risks,
        }
    }

    pub fn verdict(&self) -> Verdict {
        let script_block = self.analysis.should_block();
        let registry_high = self
            .registry_risks
            .iter()
            .any(|r| r.risk_level == RiskLevel::High);

        if script_block || registry_high {
            return Verdict::Block;
        }

        let script_suspicious = self.analysis.is_suspicious();
        let registry_warn = self
            .registry_risks
            .iter()
            .any(|r| r.risk_level == RiskLevel::Warning);

        if script_suspicious || registry_warn {
            return Verdict::Suspicious;
        }

        Verdict::Pass
    }

    pub fn render(&self) {
        println!();
        println!("SupplyGuard Analysis Report");
        println!("{}", "=".repeat(50));
        println!(
            "Package : {} v{}",
            self.analysis.package_name, self.analysis.package_version
        );
        println!("File    : {}", self.file_path);
        println!();

        // ── Install script analysis ───────────────────────────────────────────
        if self.analysis.scripts.is_empty() {
            println!("No install scripts found — nothing to analyze.");
            println!();
        } else {
            for script in &self.analysis.scripts {
                let score = &script.risk_score;
                println!("[{}] {} script", score.severity.as_str(), script.script_name);
                println!("  Script    : {}", script.script_content);
                println!(
                    "  Risk Score: {}/100  |  Confidence: {:.0}%  |  Threats: {}",
                    score.total,
                    score.confidence * 100.0,
                    score.threat_count
                );
                if !script.threats.is_empty() {
                    println!("  Indicators:");
                    for threat in &script.threats {
                        let (cat, detail, evidence) = describe_threat(threat);
                        println!("    • [{:<13}] {:<35} — {}", cat, detail, evidence);
                    }
                }
                println!();
            }
        }

        // ── Registry section ──────────────────────────────────────────────────
        if !self.registry_risks.is_empty() {
            println!("Registry Metadata Check");
            println!("{}", "=".repeat(50));

            let flagged: Vec<&RegistryRisk> = self
                .registry_risks
                .iter()
                .filter(|r| r.risk_level != RiskLevel::Ok)
                .collect();
            let clean_count = self.registry_risks.len() - flagged.len();

            for risk in &flagged {
                println!("[{}] {}", risk.risk_level.as_str(), risk.package_name);
                if let Some(ref ver) = risk.latest_version {
                    println!("  Latest      : {}", ver);
                }
                if let Some(days) = risk.age_days {
                    println!("  Age         : {} day(s)", days);
                }
                if let Some(dl) = risk.download_count {
                    println!("  Downloads   : {} last month", fmt_number(dl));
                }
                if let Some(n) = risk.maintainer_count {
                    println!("  Maintainers : {}", n);
                }
                if !risk.findings.is_empty() {
                    println!("  Findings    :");
                    for f in &risk.findings {
                        println!("    • {}", describe_registry_finding(f));
                    }
                }
                println!();
            }

            if clean_count > 0 {
                println!(
                    "  {} / {} dependencies clean",
                    clean_count,
                    self.registry_risks.len()
                );
            }
            println!();
        }

        // ── Verdict ───────────────────────────────────────────────────────────
        println!("{}", "=".repeat(50));
        println!("VERDICT: {}", self.verdict().message());
    }
}

// ── Formatting helpers ────────────────────────────────────────────────────────

fn describe_threat(threat: &ThreatIndicator) -> (&'static str, String, String) {
    match threat {
        ThreatIndicator::NetworkActivity(n) => {
            ("Network", n.pattern_type.clone(), n.evidence.clone())
        }
        ThreatIndicator::DataExfiltration(e) => {
            ("Exfiltration", e.target.clone(), e.evidence.clone())
        }
        ThreatIndicator::ProcessExecution(p) => {
            ("Execution", p.method.clone(), p.evidence.clone())
        }
        ThreatIndicator::FileSystemTampering(f) => {
            ("FileSystem", f.operation.clone(), f.evidence.clone())
        }
        ThreatIndicator::Obfuscation(o) => {
            ("Obfuscation", o.technique.clone(), o.evidence.clone())
        }
    }
}

fn describe_registry_finding(f: &RegistryFinding) -> String {
    match f {
        RegistryFinding::NewlyPublished { age_days } => {
            format!("Newly published: {} day(s) old — high-risk window", age_days)
        }
        RegistryFinding::PossibleTyposquat { similar_to, distance } => {
            format!(
                "Possible typosquat of '{}' (edit distance {})",
                similar_to, distance
            )
        }
        RegistryFinding::SingleMaintainer => {
            "Single maintainer — account compromise is high impact".to_string()
        }
        RegistryFinding::LowDownloads { count } => {
            format!("Low download count: {} last month", fmt_number(*count))
        }
        RegistryFinding::FetchFailed { reason } => {
            format!("Could not fetch registry data: {}", reason)
        }
    }
}

fn fmt_number(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut result = String::new();
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            result.push(',');
        }
        result.push(b as char);
    }
    result
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyser::AnalysisResult;
    use crate::registry::{RegistryFinding, RegistryRisk, RiskLevel};

    fn clean_analysis() -> AnalysisResult {
        AnalysisResult {
            package_name: "test-pkg".to_string(),
            package_version: "1.0.0".to_string(),
            scripts: vec![],
        }
    }

    fn risk(level: RiskLevel, findings: Vec<RegistryFinding>) -> RegistryRisk {
        RegistryRisk {
            package_name: "dep".to_string(),
            latest_version: None,
            age_days: None,
            maintainer_count: None,
            download_count: None,
            findings,
            risk_level: level,
        }
    }

    #[test]
    fn test_verdict_pass_when_no_signals() {
        let report = Report::new("p.json", clean_analysis(), vec![]);
        assert_eq!(report.verdict(), Verdict::Pass);
    }

    #[test]
    fn test_verdict_block_on_registry_high() {
        let report = Report::new(
            "p.json",
            clean_analysis(),
            vec![risk(
                RiskLevel::High,
                vec![RegistryFinding::NewlyPublished { age_days: 1 }],
            )],
        );
        assert_eq!(report.verdict(), Verdict::Block);
    }

    #[test]
    fn test_verdict_suspicious_on_registry_warning() {
        let report = Report::new(
            "p.json",
            clean_analysis(),
            vec![risk(RiskLevel::Warning, vec![RegistryFinding::SingleMaintainer])],
        );
        assert_eq!(report.verdict(), Verdict::Suspicious);
    }

    #[test]
    fn test_verdict_block_beats_suspicious() {
        // High-risk dep + a warn dep → still Block
        let report = Report::new(
            "p.json",
            clean_analysis(),
            vec![
                risk(RiskLevel::Warning, vec![RegistryFinding::SingleMaintainer]),
                risk(
                    RiskLevel::High,
                    vec![RegistryFinding::NewlyPublished { age_days: 0 }],
                ),
            ],
        );
        assert_eq!(report.verdict(), Verdict::Block);
    }

    #[test]
    fn test_verdict_pass_with_only_ok_registry() {
        let report = Report::new("p.json", clean_analysis(), vec![risk(RiskLevel::Ok, vec![])]);
        assert_eq!(report.verdict(), Verdict::Pass);
    }

    #[test]
    fn test_fmt_number() {
        assert_eq!(fmt_number(0), "0");
        assert_eq!(fmt_number(999), "999");
        assert_eq!(fmt_number(1_000), "1,000");
        assert_eq!(fmt_number(1_234_567), "1,234,567");
    }
}
