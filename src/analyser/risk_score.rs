use super::threat::ThreatIndicator;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=20 => Severity::Low,
            21..=50 => Severity::Medium,
            51..=75 => Severity::High,
            _ => Severity::Critical,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RiskScore {
    pub total: u8,
    pub confidence: f32,
    pub severity: Severity,
    pub threat_count: usize,
    pub indicator_breakdown: IndicatorBreakdown,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IndicatorBreakdown {
    pub network_activity: usize,
    pub data_exfiltration: usize,
    pub process_execution: usize,
    pub file_system_tampering: usize,
    pub obfuscation: usize,
}

impl RiskScore {
    pub fn calculate(threats: &[ThreatIndicator]) -> Self {
        let mut total_weight: u32 = 0;
        let mut breakdown = IndicatorBreakdown {
            network_activity: 0,
            data_exfiltration: 0,
            process_execution: 0,
            file_system_tampering: 0,
            obfuscation: 0,
        };

        for threat in threats {
            let weight = match threat {
                ThreatIndicator::NetworkActivity(n) => {
                    breakdown.network_activity += 1;
                    n.risk_weight as u32
                }
                ThreatIndicator::DataExfiltration(e) => {
                    breakdown.data_exfiltration += 1;
                    e.risk_weight as u32
                }
                ThreatIndicator::ProcessExecution(p) => {
                    breakdown.process_execution += 1;
                    p.risk_weight as u32
                }
                ThreatIndicator::FileSystemTampering(f) => {
                    breakdown.file_system_tampering += 1;
                    f.risk_weight as u32
                }
                ThreatIndicator::Obfuscation(o) => {
                    breakdown.obfuscation += 1;
                    o.risk_weight as u32
                }
            };
            total_weight += weight;
        }

        // Cap at 100
        let total = std::cmp::min(total_weight as u8, 100);

        // Calculate confidence based on number and diversity of indicators
        let total_categories = [
            breakdown.network_activity,
            breakdown.data_exfiltration,
            breakdown.process_execution,
            breakdown.file_system_tampering,
            breakdown.obfuscation,
        ]
        .iter()
        .filter(|&&count| count > 0)
        .count();

        let confidence = if threats.is_empty() {
            0.0
        } else {
            // Higher confidence when multiple threat categories are present
            let diversity_factor = (total_categories as f32 / 5.0) * 0.4;
            let count_factor = (threats.len().min(10) as f32 / 10.0) * 0.6;
            diversity_factor + count_factor
        };

        let severity = Severity::from_score(total);

        RiskScore {
            total,
            confidence,
            severity,
            threat_count: threats.len(),
            indicator_breakdown: breakdown,
        }
    }

    pub fn is_suspicious(&self) -> bool {
        self.total > 50 || (self.total > 30 && self.confidence > 0.7)
    }

    pub fn should_block(&self) -> bool {
        self.severity == Severity::Critical
            || (self.severity == Severity::High && self.confidence > 0.6)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyser::threat::{NetworkPattern, ExfiltrationVector};

    #[test]
    fn test_severity_classification() {
        assert_eq!(Severity::from_score(10), Severity::Low);
        assert_eq!(Severity::from_score(35), Severity::Medium);
        assert_eq!(Severity::from_score(60), Severity::High);
        assert_eq!(Severity::from_score(90), Severity::Critical);
    }

    #[test]
    fn test_risk_calculation() {
        let threats = vec![
            ThreatIndicator::NetworkActivity(NetworkPattern {
                pattern_type: "HTTP client".to_string(),
                evidence: "require('https')".to_string(),
                risk_weight: 15,
            }),
            ThreatIndicator::DataExfiltration(ExfiltrationVector {
                target: "Env vars".to_string(),
                evidence: "process.env".to_string(),
                risk_weight: 10,
            }),
        ];

        let score = RiskScore::calculate(&threats);
        assert_eq!(score.total, 25);
        assert_eq!(score.threat_count, 2);
        assert_eq!(score.severity, Severity::Medium);
    }
}
