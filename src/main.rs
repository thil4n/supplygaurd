mod analyser;
mod parser;
mod registry;
mod report;
mod scanner;

use report::{Report, Verdict};
use scanner::ScanConfig;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let offline = args.iter().any(|a| a == "--offline");
    let max_depth: usize = args
        .iter()
        .position(|a| a == "--depth")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(2);
    let file_path = args
        .iter()
        .skip(1)
        .find(|a| !a.starts_with("--") && args.iter().position(|x| x == "--depth").map(|i| &args[i + 1]) != Some(a))
        .map(|s| s.as_str())
        .unwrap_or("package.json");

    eprintln!("Scanning: {}", file_path);

    let pkg = parser::parse_content(file_path)?;
    let analysis = analyser::analyze(&pkg);

    let scan = if offline {
        eprintln!("(registry check skipped — offline mode)");
        None
    } else {
        // Collect dependencies + devDependencies as (name, version) pairs.
        let all_deps: Vec<(String, String)> = pkg
            .dependencies
            .iter()
            .chain(pkg.dev_dependencies.iter())
            .flat_map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())))
            .collect();

        if all_deps.is_empty() {
            None
        } else {
            eprintln!("Scanning dependency tree (max depth {})...", max_depth);
            let checker = registry::RegistryChecker::new();
            let config = ScanConfig { max_depth };
            let result = scanner::scan_dependencies(&checker, &all_deps, &config);
            Some(result)
        }
    };

    let report = Report::new(file_path, analysis, scan);
    report.render();

    if report.verdict() == Verdict::Block {
        std::process::exit(1);
    }

    Ok(())
}
