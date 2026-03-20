mod parser;
mod analyser;

use analyser::threat::ThreatIndicator;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let file_path = args.get(1).map(|s| s.as_str()).unwrap_or("package.json");

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
    if result.should_block() {
        println!("VERDICT: BLOCK — Do not install this package.");
        std::process::exit(1);
    } else if result.is_suspicious() {
        println!("VERDICT: SUSPICIOUS — Manual review recommended before installing.");
    } else {
        println!("VERDICT: PASS — No significant threats detected.");
    }

    Ok(())
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
