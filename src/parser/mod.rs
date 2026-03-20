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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs as stdfs;

    #[test]
    fn test_parse_benign_dataset() {
        let result = parse_content("datasets/benign/package.json");
        assert!(result.is_ok());
        let pkg = result.unwrap();
        assert!(pkg.name.is_some());
    }

    #[test]
    fn test_parse_malicious_dataset() {
        let result = parse_content("datasets/malicious/package.json");
        assert!(result.is_ok());
        let pkg = result.unwrap();
        assert_eq!(pkg.name.as_deref(), Some("totally-legit-utils"));
        assert_eq!(pkg.version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn test_parse_missing_file() {
        let result = parse_content("no_such_file_supplygaurd.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_json() {
        let path = env::temp_dir().join("supplygaurd_test_invalid.json");
        stdfs::write(&path, "not valid json {{{").unwrap();
        let result = parse_content(path.to_str().unwrap());
        stdfs::remove_file(&path).ok();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_minimal_package() {
        let path = env::temp_dir().join("supplygaurd_test_minimal.json");
        stdfs::write(&path, r#"{"name": "minimal", "version": "0.1.0"}"#).unwrap();
        let result = parse_content(path.to_str().unwrap());
        stdfs::remove_file(&path).ok();
        assert!(result.is_ok());
        let pkg = result.unwrap();
        assert_eq!(pkg.name.as_deref(), Some("minimal"));
        assert!(pkg.scripts.is_none());
    }

    #[test]
    fn test_parse_all_optional_fields_absent() {
        let path = env::temp_dir().join("supplygaurd_test_empty_pkg.json");
        stdfs::write(&path, r#"{}"#).unwrap();
        let result = parse_content(path.to_str().unwrap());
        stdfs::remove_file(&path).ok();
        assert!(result.is_ok());
        let pkg = result.unwrap();
        assert!(pkg.name.is_none());
        assert!(pkg.version.is_none());
        assert!(pkg.scripts.is_none());
    }

    #[test]
    fn test_parse_package_with_scripts() {
        let path = env::temp_dir().join("supplygaurd_test_scripts.json");
        let content = r#"{"name":"test","version":"1.0.0","scripts":{"preinstall":"echo hi","build":"tsc"}}"#;
        stdfs::write(&path, content).unwrap();
        let result = parse_content(path.to_str().unwrap());
        stdfs::remove_file(&path).ok();
        assert!(result.is_ok());
        let pkg = result.unwrap();
        let scripts = pkg.scripts.unwrap();
        assert_eq!(scripts.get("preinstall").map(|s| s.as_str()), Some("echo hi"));
        assert_eq!(scripts.get("build").map(|s| s.as_str()), Some("tsc"));
    }
}
