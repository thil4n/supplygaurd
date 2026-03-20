mod parser;
mod analyser;
mod registry;

use analyser::threat::ThreatIndicator;
use registry::{RegistryFinding, RiskLevel};
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let offline = args.iter().any(|a| a == "--offline");
    let file_path = args
        .iter()
        .skip(1)
        .find(|a| !a.starts_with("--"))
        .map(|s| s.as_str())
        .unwrap_or("package.json");

    eprintln!("Scanning: {}", file_path);

    let pkg = parser::parse_content(file_path)?;
    let result = analyser::analyze(&pkg);

    println!();
    println!("SupplyGuard Analysis Report");
    println!("{}", "=".repeat(50));
    println!("Package : {} v{}", result.package_name, result.package_version);
    println!("File    : {}", file_path);
    println!();

    if result.scripts.is_empty() {
        println!("No install scripts found — nothing to analyze.");
        println!();
        println!("VERDICT: PASS — No install scripts present.");
        return Ok(());
    }

    for analysis in &result.scripts {
        let score = &analysis.risk_score;
        println!(
            "[{}] {} script",
            score.severity.as_str(),
            analysis.script_name
        );
        println!("  Script    : {}", analysis.script_content);
        println!(
            "  Risk Score: {}/100  |  Confidence: {:.0}%  |  Threats: {}",
            score.total,
            score.confidence * 100.0,
            score.threat_count
        );

        if !analysis.threats.is_empty() {
            println!("  Indicators:");
            for threat in &analysis.threats {
                let (category, detail, evidence) = describe_threat(threat);
                println!("    • [{:<13}] {:<35} — {}", category, detail, evidence);
            }
        }
        println!();
    }

    println!("{}", "=".repeat(50));
    let script_verdict = if result.should_block() {
        "BLOCK"
    } else if result.is_suspicious() {
        "SUSPICIOUS"
    } else {
        "PASS"
    };

    // ── Registry metadata check ───────────────────────────────────────────────
    let mut registry_has_high = false;
    let mut registry_has_warn = false;

    if !offline {
        let all_deps: Vec<String> = {
            let mut v = Vec::new();
            if let Some(d) = &pkg.dependencies {
                v.extend(d.keys().cloned());
            }
            if let Some(d) = &pkg.dev_dependencies {
                v.extend(d.keys().cloned());
            }
            v
        };

        if !all_deps.is_empty() {
            println!();
            println!("Registry Metadata Check");
            println!("{}", "=".repeat(50));
            eprintln!("Scanning {} dependencies via registry.npmjs.org...", all_deps.len());
            eprintln!();

            let checker = registry::RegistryChecker::new();
            let mut risks: Vec<registry::RegistryRisk> = all_deps
                .iter()
                .map(|name| {
                    eprint!("  checking {} ... ", name);
                    let r = checker.check(name);
                    eprintln!("{}", r.risk_level.as_str());
                    r
                })
                .collect();

            // Sort highest risk first.
            risks.sort_by(|a, b| b.risk_level.cmp(&a.risk_level));

            println!();
            let mut clean_count = 0usize;
            for risk in &risks {
                match risk.risk_level {
                    RiskLevel::High => registry_has_high = true,
                    RiskLevel::Warning => registry_has_warn = true,
                    RiskLevel::Ok => {
                        clean_count += 1;
                        continue;
                    }
                }
                println!("[{}] {}", risk.risk_level.as_str(), risk.package_name);
                if let Some(ref ver) = risk.latest_version {
                    println!("  Latest   : {}", ver);
                }
                if let Some(days) = risk.age_days {
                    println!("  Age      : {} day(s)", days);
                }
                if let Some(dl) = risk.download_count {
                    println!("  Downloads: {} last month", fmt_number(dl));
                }
                if let Some(n) = risk.maintainer_count {
                    println!("  Maintainers: {}", n);
                }
                if !risk.findings.is_empty() {
                    println!("  Findings :");
                    for f in &risk.findings {
                        println!("    • {}", describe_registry_finding(f));
                    }
                }
                println!();
            }

            if clean_count > 0 {
                println!("  {} / {} dependencies clean", clean_count, risks.len());
            }
        }
    } else {
        eprintln!("(registry check skipped — offline mode)");
    }

    // ── Final verdict ─────────────────────────────────────────────────────────
    println!();
    println!("{}", "=".repeat(50));
    let block = result.should_block() || registry_has_high;
    let suspicious = result.is_suspicious() || registry_has_warn;

    if block {
        println!("VERDICT: BLOCK — Do not install this package.");
        if script_verdict == "PASS" && registry_has_high {
            println!("  (registry metadata flagged a high-risk dependency)");
        }
        std::process::exit(1);
    } else if suspicious {
        println!("VERDICT: SUSPICIOUS — Manual review recommended before installing.");
    } else {
        println!("VERDICT: PASS — No significant threats detected.");
    }

    Ok(())
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
