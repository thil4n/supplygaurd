mod package_json;

use crate::package_json::PackageJson;

use std::fs;
use serde_json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file_path = "datasets/benign/package.json";

    let content = fs::read_to_string(file_path)?;
    println!("Package.json read successfully\n");

    let pkg: PackageJson = serde_json::from_str(&content)?;
    println!("Parsed PackageJson: {:?}", pkg);

    Ok(())
}
