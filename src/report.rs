use crate::analyser::threat::ThreatIndicator;
use crate::analyser::AnalysisResult;
use crate::registry::{RegistryFinding, RiskLevel};
use crate::scanner::{DependencyNode, ScanResult};

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
    /// `None` when running in offline mode.
    pub scan: Option<ScanResult>,
}

impl Report {
    pub fn new(
        file_path: impl Into<String>,
        analysis: AnalysisResult,
        scan: Option<ScanResult>,
    ) -> Self {
        Self {
            file_path: file_path.into(),
            analysis,
            scan,
        }
    }

    pub fn verdict(&self) -> Verdict {
        let script_block = self.analysis.should_block();
        let scan_block = self.scan.as_ref().is_some_and(|s| s.has_block());

        if script_block || scan_block {
            return Verdict::Block;
        }

        let script_suspicious = self.analysis.is_suspicious();
        let scan_suspicious = self.scan.as_ref().is_some_and(|s| s.has_suspicious());

        if script_suspicious || scan_suspicious {
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

        // ── Dependency tree scan ──────────────────────────────────────────────
        if let Some(ref scan) = self.scan {
            println!("Dependency Tree Scan ({} scanned, {} skipped)",
                scan.total_scanned, scan.total_skipped);
            println!("{}", "=".repeat(50));

            let mut flagged = 0usize;
            for node in &scan.tree {
                flagged += render_node(node, 0);
            }

            let clean = scan.total_scanned.saturating_sub(flagged);
            if clean > 0 {
                println!(
                    "  {} / {} dependencies clean",
                    clean, scan.total_scanned
                );
            }
            println!();
        }

        // ── Verdict ───────────────────────────────────────────────────────────
        println!("{}", "=".repeat(50));
        println!("VERDICT: {}", self.verdict().message());
    }
}

/// Render a dependency node and its children. Returns count of flagged nodes.
fn render_node(node: &DependencyNode, indent: usize) -> usize {
    let is_flagged = node.registry_risk.risk_level != RiskLevel::Ok
        || node.analysis.is_suspicious()
        || node.analysis.should_block();

    let mut count = 0;
    let pad = "  ".repeat(indent + 1);

    if is_flagged {
        count += 1;

        // Registry risk line
        let risk_label = if node.analysis.should_block() {
            "BLOCK"
        } else if node.analysis.is_suspicious() {
            node.registry_risk.risk_level.as_str()
        } else {
            node.registry_risk.risk_level.as_str()
        };

        println!(
            "{}[{}] {} v{}",
            pad, risk_label, node.name, node.version
        );

        // Registry findings
        for f in &node.registry_risk.findings {
            println!("{}  • {}", pad, describe_registry_finding(f));
        }

        // Script findings (if any install scripts had threats)
        for script in &node.analysis.scripts {
            if script.risk_score.total > 0 {
                println!(
                    "{}  {} script — score {}/100",
                    pad, script.script_name, script.risk_score.total
                );
                for threat in &script.threats {
                    let (cat, detail, evidence) = describe_threat(threat);
                    println!("{}    [{:<13}] {:<30} — {}", pad, cat, detail, evidence);
                }
            }
        }
        println!();
    }

    // Recurse into children
    for child in &node.children {
        count += render_node(child, indent + 1);
    }

    count
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
        RegistryFinding::LowTrustPackage { reason } => {
            format!("Low trust: {}", reason)
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
    use crate::registry::{RegistryRisk, RiskLevel};
    use crate::scanner::{DependencyNode, ScanResult};

    fn clean_analysis() -> AnalysisResult {
        AnalysisResult {
            package_name: "test-pkg".to_string(),
            package_version: "1.0.0".to_string(),
            scripts: vec![],
        }
    }

    fn dummy_risk(level: RiskLevel) -> RegistryRisk {
        RegistryRisk {
            package_name: "dep".to_string(),
            latest_version: None,
            age_days: None,
            maintainer_count: None,
            download_count: None,
            findings: vec![],
            risk_level: level,
        }
    }

    fn scan_with(nodes: Vec<DependencyNode>) -> ScanResult {
        let total = nodes.len();
        ScanResult { tree: nodes, total_scanned: total, total_skipped: 0 }
    }

    fn dep_node(name: &str, level: RiskLevel) -> DependencyNode {
        DependencyNode {
            name: name.into(),
            version: "1.0.0".into(),
            depth: 0,
            analysis: clean_analysis(),
            registry_risk: dummy_risk(level),
            children: vec![],
        }
    }

    // ── Verdict tests (offline / no scan) ─────────────────────────────────────

    #[test]
    fn test_verdict_pass_offline() {
        let report = Report::new("p.json", clean_analysis(), None);
        assert_eq!(report.verdict(), Verdict::Pass);
    }

    #[test]
    fn test_verdict_pass_empty_scan() {
        let report = Report::new("p.json", clean_analysis(), Some(scan_with(vec![])));
        assert_eq!(report.verdict(), Verdict::Pass);
    }

    // ── Verdict tests (with scan) ─────────────────────────────────────────────

    #[test]
    fn test_verdict_block_on_high_risk_dep() {
        let report = Report::new(
            "p.json",
            clean_analysis(),
            Some(scan_with(vec![dep_node("bad", RiskLevel::High)])),
        );
        assert_eq!(report.verdict(), Verdict::Block);
    }

    #[test]
    fn test_verdict_suspicious_on_warning_dep() {
        let report = Report::new(
            "p.json",
            clean_analysis(),
            Some(scan_with(vec![dep_node("warn", RiskLevel::Warning)])),
        );
        assert_eq!(report.verdict(), Verdict::Suspicious);
    }

    #[test]
    fn test_verdict_block_on_nested_high() {
        let child = dep_node("deep-bad", RiskLevel::High);
        let parent = DependencyNode {
            children: vec![child],
            ..dep_node("parent", RiskLevel::Ok)
        };
        let report = Report::new(
            "p.json",
            clean_analysis(),
            Some(scan_with(vec![parent])),
        );
        assert_eq!(report.verdict(), Verdict::Block);
    }

    #[test]
    fn test_verdict_pass_all_clean() {
        let report = Report::new(
            "p.json",
            clean_analysis(),
            Some(scan_with(vec![
                dep_node("a", RiskLevel::Ok),
                dep_node("b", RiskLevel::Ok),
            ])),
        );
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
