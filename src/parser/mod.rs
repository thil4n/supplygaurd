mod package_json;

use crate::parser::package_json::PackageJson;

use serde_json;
use std::fs;

pub fn extract_install_scripts(pkg: &PackageJson) -> Vec<(&String, &String)> {
    pkg.scripts
        .iter()
        .flat_map(|m| m.iter())
        .filter(|(k, _)| k == &"preinstall" || k == &"install" || k == &"postinstall")
        .collect()
}

pub fn script_complexity(script: &str) -> usize {
    script.split_whitespace().count()
}

pub fn parse_content(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::metadata(file_path)?;
    if metadata.len() > 1024 * 1024 {
        return Err("package.json too large".into());
    }

    let content = fs::read_to_string(file_path)?;
    println!("Package.json read successfully\n");

    let pkg: PackageJson = serde_json::from_str(&content)?;
    println!("Parsed PackageJson: {:?}", pkg);

    Ok(())
}
