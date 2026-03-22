use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct PackageJson {
    pub name: Option<String>,
    pub version: Option<String>,
    pub scripts: Option<HashMap<String, String>>,
    pub dependencies: Option<HashMap<String, String>>,
    pub dev_dependencies: Option<HashMap<String, String>>,
}

impl PackageJson {
    /// Build a PackageJson from registry metadata (for transitive scanning).
    pub fn from_registry(
        name: &str,
        version: &str,
        scripts: Option<HashMap<String, String>>,
    ) -> Self {
        Self {
            name: Some(name.to_string()),
            version: Some(version.to_string()),
            scripts,
            dependencies: None,
            dev_dependencies: None,
        }
    }
}
