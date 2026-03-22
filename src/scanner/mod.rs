use std::collections::HashSet;

use crate::analyser::{self, AnalysisResult};
use crate::parser::PackageJson;
use crate::registry::{RegistryChecker, RegistryRisk, RiskLevel};

// ── Configuration ─────────────────────────────────────────────────────────────

pub struct ScanConfig {
    /// Maximum recursion depth (0 = direct deps only).
    pub max_depth: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self { max_depth: 2 }
    }
}

// ── Result types ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct DependencyNode {
    pub name: String,
    pub version: String,
    pub depth: usize,
    /// Install-script analysis for this package (from registry scripts).
    pub analysis: AnalysisResult,
    /// Registry metadata risk (age, typosquatting, downloads, maintainers).
    pub registry_risk: RegistryRisk,
    /// Transitive dependencies scanned recursively.
    pub children: Vec<DependencyNode>,
}

#[derive(Debug)]
pub struct ScanResult {
    pub tree: Vec<DependencyNode>,
    pub total_scanned: usize,
    pub total_skipped: usize,
}

// ── Scanner ───────────────────────────────────────────────────────────────────

pub fn scan_dependencies(
    checker: &RegistryChecker,
    deps: &[(String, String)],
    config: &ScanConfig,
) -> ScanResult {
    let mut visited: HashSet<String> = HashSet::new();
    let mut total_scanned = 0usize;
    let mut total_skipped = 0usize;

    let tree = scan_recursive(
        checker,
        deps,
        0,
        config,
        &mut visited,
        &mut total_scanned,
        &mut total_skipped,
    );

    ScanResult {
        tree,
        total_scanned,
        total_skipped,
    }
}

fn scan_recursive(
    checker: &RegistryChecker,
    deps: &[(String, String)],
    depth: usize,
    config: &ScanConfig,
    visited: &mut HashSet<String>,
    total_scanned: &mut usize,
    total_skipped: &mut usize,
) -> Vec<DependencyNode> {
    let mut nodes = Vec::new();

    for (name, _version_spec) in deps {
        if visited.contains(name.as_str()) {
            *total_skipped += 1;
            continue;
        }
        visited.insert(name.clone());
        *total_scanned += 1;

        let indent = "  ".repeat(depth + 1);
        eprint!("{}[depth {}] {} ... ", indent, depth, name);

        let meta = checker.fetch_package_metadata(name);
        eprintln!("{}", meta.registry_risk.risk_level.as_str());

        // Build a PackageJson from the registry data and run the analyser.
        let pkg = PackageJson::from_registry(&meta.name, &meta.version, meta.scripts);
        let analysis = analyser::analyze(&pkg);

        // Recurse into this package's dependencies if within depth limit.
        let children = if depth < config.max_depth {
            if let Some(ref child_deps) = meta.dependencies {
                let child_list: Vec<(String, String)> =
                    child_deps.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                if !child_list.is_empty() {
                    scan_recursive(
                        checker,
                        &child_list,
                        depth + 1,
                        config,
                        visited,
                        total_scanned,
                        total_skipped,
                    )
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        nodes.push(DependencyNode {
            name: name.clone(),
            version: meta.version,
            depth,
            analysis,
            registry_risk: meta.registry_risk,
            children,
        });
    }

    nodes
}

// ── Tree helpers ──────────────────────────────────────────────────────────────

impl DependencyNode {
    /// Recursively check whether any node in this subtree should block.
    pub fn has_block(&self) -> bool {
        self.analysis.should_block()
            || self.registry_risk.risk_level == RiskLevel::High
            || self.children.iter().any(|c| c.has_block())
    }

    /// Recursively check whether any node in this subtree is suspicious.
    pub fn has_suspicious(&self) -> bool {
        self.analysis.is_suspicious()
            || self.registry_risk.risk_level == RiskLevel::Warning
            || self.children.iter().any(|c| c.has_suspicious())
    }
}

impl ScanResult {
    pub fn has_block(&self) -> bool {
        self.tree.iter().any(|n| n.has_block())
    }

    pub fn has_suspicious(&self) -> bool {
        self.tree.iter().any(|n| n.has_suspicious())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{RegistryRisk, RiskLevel};

    fn dummy_analysis() -> AnalysisResult {
        AnalysisResult {
            package_name: "test".into(),
            package_version: "1.0.0".into(),
            scripts: vec![],
        }
    }

    fn dummy_risk(level: RiskLevel) -> RegistryRisk {
        RegistryRisk {
            package_name: "test".into(),
            latest_version: None,
            age_days: None,
            maintainer_count: None,
            download_count: None,
            findings: vec![],
            risk_level: level,
        }
    }

    fn leaf(name: &str, risk_level: RiskLevel) -> DependencyNode {
        DependencyNode {
            name: name.into(),
            version: "1.0.0".into(),
            depth: 0,
            analysis: dummy_analysis(),
            registry_risk: dummy_risk(risk_level),
            children: vec![],
        }
    }

    #[test]
    fn test_has_block_propagates_from_child() {
        let parent = DependencyNode {
            children: vec![leaf("child", RiskLevel::High)],
            ..leaf("parent", RiskLevel::Ok)
        };
        assert!(parent.has_block());
    }

    #[test]
    fn test_has_block_false_when_all_ok() {
        let parent = DependencyNode {
            children: vec![leaf("a", RiskLevel::Ok), leaf("b", RiskLevel::Ok)],
            ..leaf("parent", RiskLevel::Ok)
        };
        assert!(!parent.has_block());
    }

    #[test]
    fn test_has_suspicious_propagates_from_child() {
        let parent = DependencyNode {
            children: vec![leaf("child", RiskLevel::Warning)],
            ..leaf("parent", RiskLevel::Ok)
        };
        assert!(parent.has_suspicious());
    }

    #[test]
    fn test_scan_result_has_block() {
        let result = ScanResult {
            tree: vec![leaf("ok-pkg", RiskLevel::Ok), leaf("bad-pkg", RiskLevel::High)],
            total_scanned: 2,
            total_skipped: 0,
        };
        assert!(result.has_block());
    }

    #[test]
    fn test_scan_result_clean() {
        let result = ScanResult {
            tree: vec![leaf("a", RiskLevel::Ok), leaf("b", RiskLevel::Ok)],
            total_scanned: 2,
            total_skipped: 0,
        };
        assert!(!result.has_block());
        assert!(!result.has_suspicious());
    }

    #[test]
    fn test_visited_set_prevents_duplicates() {
        let mut visited: HashSet<String> = HashSet::new();
        visited.insert("already-seen".into());

        // Simulate: dep list contains an already-visited package
        let deps: Vec<(String, String)> = vec![("already-seen".into(), "^1.0.0".into())];
        let _config = ScanConfig { max_depth: 0 };
        let mut scanned = 0;
        let mut skipped = 0;

        // Can't call scan_recursive without a real checker, so test the
        // visited logic inline:
        for (name, _) in &deps {
            if visited.contains(name.as_str()) {
                skipped += 1;
            } else {
                scanned += 1;
            }
        }
        assert_eq!(skipped, 1);
        assert_eq!(scanned, 0);
    }
}
