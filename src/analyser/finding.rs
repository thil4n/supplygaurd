#[derive(Debug)]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug)]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
}
