mod analyser;
mod parser;
mod registry;
mod report;

use report::{Report, Verdict};
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
    let analysis = analyser::analyze(&pkg);

    let registry_risks = if offline {
        eprintln!("(registry check skipped — offline mode)");
        vec![]
    } else {
        let all_deps: Vec<String> = pkg
            .dependencies
            .iter()
            .chain(pkg.dev_dependencies.iter())
            .flat_map(|m| m.keys().cloned())
            .collect();

        if all_deps.is_empty() {
            vec![]
        } else {
            eprintln!("Checking {} dependencies...", all_deps.len());
            let checker = registry::RegistryChecker::new();
            let mut risks: Vec<_> = all_deps
                .iter()
                .map(|name| {
                    eprint!("  {} ... ", name);
                    let r = checker.check(name);
                    eprintln!("{}", r.risk_level.as_str());
                    r
                })
                .collect();
            risks.sort_by(|a, b| b.risk_level.cmp(&a.risk_level));
            risks
        }
    };

    let report = Report::new(file_path, analysis, registry_risks);
    report.render();

    if report.verdict() == Verdict::Block {
        std::process::exit(1);
    }

    Ok(())
}
