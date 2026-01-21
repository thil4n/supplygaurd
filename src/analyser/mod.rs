mod finding;

pub fn analyze_install_scripts(pkg: &PackageJson) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(scripts) = &pkg.scripts {
        for (name, script) in scripts {
            if name == "preinstall" || name == "install" || name == "postinstall" {
                let complexity = script_complexity(script);

                if complexity > 20 {
                    findings.push(Finding {
                        severity: Severity::Medium,
                        message: format!(
                            "Complex {} script ({} tokens): {}",
                            name, complexity, script
                        ),
                    });
                } else {
                    findings.push(Finding {
                        severity: Severity::Low,
                        message: format!("{} script present: {}", name, script),
                    });
                }
            }
        }
    }

    findings
}
