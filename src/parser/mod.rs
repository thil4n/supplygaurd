mod package_json;

pub use package_json::PackageJson;

use serde_json;
use std::fs;

pub fn parse_content(file_path: &str) -> Result<PackageJson, Box<dyn std::error::Error>> {
    let metadata = fs::metadata(file_path)?;
    if metadata.len() > 1024 * 1024 {
        return Err("package.json too large".into());
    }

    let content = fs::read_to_string(file_path)?;
    let pkg: PackageJson = serde_json::from_str(&content)?;
    Ok(pkg)
}
