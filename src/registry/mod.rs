pub mod typosquat;

use chrono::{NaiveDate, Utc};
use serde::Deserialize;
use std::collections::HashMap;

// ── Public types ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum RegistryFinding {
    NewlyPublished { age_days: i64 },
    PossibleTyposquat { similar_to: String, distance: usize },
    /// Only emitted when combined with another weak signal (low downloads, new package).
    /// Single maintainer alone is normal for npm — most packages have one.
    LowTrustPackage { reason: String },
    LowDownloads { count: u64 },
    FetchFailed { reason: String },
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum RiskLevel {
    Ok,
    Warning,
    High,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            RiskLevel::Ok => "OK",
            RiskLevel::Warning => "WARN",
            RiskLevel::High => "HIGH",
        }
    }
}

#[derive(Debug)]
pub struct RegistryRisk {
    pub package_name: String,
    pub latest_version: Option<String>,
    /// Days since the current latest version was published.
    pub age_days: Option<i64>,
    pub maintainer_count: Option<usize>,
    pub download_count: Option<u64>,
    pub findings: Vec<RegistryFinding>,
    pub risk_level: RiskLevel,
}

/// Full metadata returned by `fetch_package_metadata()` for recursive scanning.
#[derive(Debug)]
pub struct PackageMetadata {
    pub name: String,
    pub version: String,
    pub scripts: Option<HashMap<String, String>>,
    pub dependencies: Option<HashMap<String, String>>,
    pub registry_risk: RegistryRisk,
}

// ── Internal serde types ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RegistryResponse {
    /// Keys are version strings plus "created" and "modified".
    time: HashMap<String, String>,
    maintainers: Option<Vec<Maintainer>>,
    #[serde(rename = "dist-tags")]
    dist_tags: HashMap<String, String>,
    versions: Option<HashMap<String, VersionInfo>>,
}

#[derive(Deserialize)]
struct VersionInfo {
    scripts: Option<HashMap<String, String>>,
    dependencies: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
struct Maintainer {
    #[allow(dead_code)]
    name: String,
}

#[derive(Deserialize)]
struct DownloadResponse {
    downloads: u64,
}

// ── RegistryChecker ───────────────────────────────────────────────────────────

pub struct RegistryChecker {
    agent: ureq::Agent,
}

impl RegistryChecker {
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(15))
            .build();
        Self { agent }
    }

    /// Fetch registry metadata and return risk assessment only (no scripts/deps).
    pub fn check(&self, package_name: &str) -> RegistryRisk {
        let (risk, _meta) = self.fetch_raw(package_name);
        risk
    }

    /// Fetch full package metadata: risk assessment + scripts + dependencies.
    /// Used by the recursive scanner to analyse transitive dependencies.
    pub fn fetch_package_metadata(&self, package_name: &str) -> PackageMetadata {
        let (risk, meta) = self.fetch_raw(package_name);
        let (scripts, dependencies) = meta
            .map(|m| {
                let latest = risk.latest_version.as_deref().unwrap_or("");
                let ver_info = m.versions.as_ref().and_then(|vs| vs.get(latest));
                (
                    ver_info.and_then(|v| v.scripts.clone()),
                    ver_info.and_then(|v| v.dependencies.clone()),
                )
            })
            .unwrap_or((None, None));

        PackageMetadata {
            name: package_name.to_string(),
            version: risk.latest_version.clone().unwrap_or_else(|| "unknown".into()),
            scripts,
            dependencies,
            registry_risk: risk,
        }
    }

    /// Shared fetch logic — returns the risk assessment and the raw response
    /// (when available) so callers can extract additional fields.
    fn fetch_raw(&self, package_name: &str) -> (RegistryRisk, Option<RegistryResponse>) {
        let mut findings = Vec::new();
        let mut latest_version = None;
        let mut age_days = None;
        let mut maintainer_count = None;
        let mut download_count = None;
        let mut raw_meta = None;

        // Typosquat check — no network needed.
        for candidate in typosquat::find_similar(package_name) {
            findings.push(RegistryFinding::PossibleTyposquat {
                similar_to: candidate.target,
                distance: candidate.distance,
            });
        }

        // Scoped packages need the slash URL-encoded.
        let encoded = package_name.replace('/', "%2F");

        // ── Registry metadata ─────────────────────────────────────────────────
        let registry_url = format!("https://registry.npmjs.org/{}", encoded);
        match self.agent.get(&registry_url).call() {
            Ok(resp) => match resp.into_json::<RegistryResponse>() {
                Ok(meta) => {
                    let latest = meta.dist_tags.get("latest").cloned();
                    latest_version = latest.clone();

                    if let Some(ref ver) = latest {
                        if let Some(ts) = meta.time.get(ver) {
                            if let Some(days) = parse_days_ago(ts) {
                                age_days = Some(days);
                                if days < 7 {
                                    findings.push(RegistryFinding::NewlyPublished { age_days: days });
                                }
                            }
                        }
                    }

                    let count = meta.maintainers.as_ref().map(|m| m.len()).unwrap_or(0);
                    maintainer_count = Some(count);

                    raw_meta = Some(meta);
                }
                Err(e) => findings.push(RegistryFinding::FetchFailed { reason: e.to_string() }),
            },
            Err(e) => findings.push(RegistryFinding::FetchFailed { reason: e.to_string() }),
        }

        // ── Download stats ────────────────────────────────────────────────────
        let dl_url = format!(
            "https://api.npmjs.org/downloads/point/last-month/{}",
            encoded
        );
        if let Ok(resp) = self.agent.get(&dl_url).call() {
            if let Ok(dl) = resp.into_json::<DownloadResponse>() {
                download_count = Some(dl.downloads);
                if dl.downloads < 1_000 {
                    findings.push(RegistryFinding::LowDownloads { count: dl.downloads });
                }
            }
        }

        // ── Combined weak signals ─────────────────────────────────────────────
        // Single maintainer alone is normal (most npm packages). Only flag it
        // when paired with another weak signal that together suggest low trust.
        let is_single_maintainer = maintainer_count == Some(1);
        let is_low_downloads = download_count.map(|d| d < 1_000).unwrap_or(false);
        let is_new = age_days.map(|d| d < 30).unwrap_or(false);

        if is_single_maintainer && (is_low_downloads || is_new) {
            let detail = if is_low_downloads && is_new {
                "Single maintainer + low downloads + recently published".to_string()
            } else if is_low_downloads {
                "Single maintainer + low downloads".to_string()
            } else {
                "Single maintainer + recently published (< 30 days)".to_string()
            };
            findings.push(RegistryFinding::LowTrustPackage { reason: detail });
        }

        let risk_level = compute_risk_level(&findings);
        let risk = RegistryRisk {
            package_name: package_name.to_string(),
            latest_version,
            age_days,
            maintainer_count,
            download_count,
            findings,
            risk_level,
        };
        (risk, raw_meta)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse "2023-01-01T12:34:56.000Z" and return how many days ago that was.
fn parse_days_ago(iso_date: &str) -> Option<i64> {
    let date_part = iso_date.split('T').next()?;
    let mut parts = date_part.split('-');
    let year: i32 = parts.next()?.parse().ok()?;
    let month: u32 = parts.next()?.parse().ok()?;
    let day: u32 = parts.next()?.parse().ok()?;
    let published = NaiveDate::from_ymd_opt(year, month, day)?;
    let today = Utc::now().date_naive();
    Some(today.signed_duration_since(published).num_days())
}

fn compute_risk_level(findings: &[RegistryFinding]) -> RiskLevel {
    for f in findings {
        match f {
            RegistryFinding::NewlyPublished { .. } | RegistryFinding::PossibleTyposquat { .. } => {
                return RiskLevel::High;
            }
            _ => {}
        }
    }
    if findings
        .iter()
        .any(|f| matches!(f, RegistryFinding::LowTrustPackage { .. } | RegistryFinding::LowDownloads { .. }))
    {
        return RiskLevel::Warning;
    }
    RiskLevel::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_days_ago ────────────────────────────────────────────────────────

    #[test]
    fn test_parse_days_ago_valid_date() {
        let result = parse_days_ago("2020-01-01T00:00:00.000Z");
        assert!(result.is_some());
        assert!(result.unwrap() > 0, "2020 date should be in the past");
    }

    #[test]
    fn test_parse_days_ago_invalid_returns_none() {
        assert!(parse_days_ago("not-a-date").is_none());
        assert!(parse_days_ago("").is_none());
    }

    #[test]
    fn test_parse_days_ago_recent_is_small() {
        let today = Utc::now().date_naive();
        let iso = format!("{}T00:00:00.000Z", today);
        let days = parse_days_ago(&iso).unwrap();
        assert_eq!(days, 0);
    }

    // ── compute_risk_level ────────────────────────────────────────────────────

    #[test]
    fn test_risk_level_empty_findings_is_ok() {
        assert_eq!(compute_risk_level(&[]), RiskLevel::Ok);
    }

    #[test]
    fn test_risk_level_newly_published_is_high() {
        let findings = vec![RegistryFinding::NewlyPublished { age_days: 2 }];
        assert_eq!(compute_risk_level(&findings), RiskLevel::High);
    }

    #[test]
    fn test_risk_level_typosquat_is_high() {
        let findings = vec![RegistryFinding::PossibleTyposquat {
            similar_to: "lodash".to_string(),
            distance: 1,
        }];
        assert_eq!(compute_risk_level(&findings), RiskLevel::High);
    }

    #[test]
    fn test_risk_level_low_trust_is_warning() {
        let findings = vec![RegistryFinding::LowTrustPackage {
            reason: "Single maintainer + low downloads".into(),
        }];
        assert_eq!(compute_risk_level(&findings), RiskLevel::Warning);
    }

    #[test]
    fn test_risk_level_low_downloads_is_warning() {
        let findings = vec![RegistryFinding::LowDownloads { count: 42 }];
        assert_eq!(compute_risk_level(&findings), RiskLevel::Warning);
    }

    #[test]
    fn test_risk_level_fetch_failed_is_ok() {
        // A network failure alone doesn't mean the package is malicious.
        let findings = vec![RegistryFinding::FetchFailed { reason: "timeout".to_string() }];
        assert_eq!(compute_risk_level(&findings), RiskLevel::Ok);
    }

    #[test]
    fn test_risk_level_high_beats_warning() {
        // If both a typosquat hit and low-trust are present, result is High.
        let findings = vec![
            RegistryFinding::LowTrustPackage { reason: "test".into() },
            RegistryFinding::NewlyPublished { age_days: 1 },
        ];
        assert_eq!(compute_risk_level(&findings), RiskLevel::High);
    }

    // ── RiskLevel ordering ────────────────────────────────────────────────────

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Ok < RiskLevel::Warning);
        assert!(RiskLevel::Warning < RiskLevel::High);
    }
}
