use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatCategory {
    Keylogger,
    InfoStealer,
    RemoteAccessTrojan,
    SpywarePersistence,
    NetworkSpy,
    SuspiciousDropper,
    ScreenRecorder,
    TelemetryTracker,
    RansomwareBehavior,
    ObfuscatedSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    pub id: String,
    pub name: String,
    pub category: ThreatCategory,
    pub severity: ThreatSeverity,
    pub description: String,
    pub file_path: Option<String>,
    pub pid: Option<u32>,
    pub registry_key: Option<String>,
    pub remote_addr: Option<String>,
    pub detected_at: String,
    pub status: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub scan_type: String,
    pub total_scanned: usize,
    pub threats: Vec<Threat>,
    pub elapsed_ms: u64,
    pub timestamp: String,
    pub system_status: String,
    pub groq_ai_summary: Option<String>,
    pub desourced_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredProcess {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
    pub cpu_usage: f32,
    pub memory_bytes: u64,
    pub is_suspicious: bool,
    pub suspicion_reason: Option<String>,
    pub parent_pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutorunEntry {
    pub id: String,
    pub name: String,
    pub source: String,
    pub location: String,
    pub command: String,
    pub is_suspicious: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSocketEntry {
    pub pid: u32,
    pub process_name: String,
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub is_suspicious: bool,
    pub risk_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineItem {
    pub id: String,
    pub original_path: String,
    pub quarantine_path: String,
    pub threat_name: String,
    pub file_size_bytes: u64,
    pub sha256_hash: String,
    pub quarantined_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSummary {
    pub total_processes: usize,
    pub suspicious_processes: usize,
    pub total_autoruns: usize,
    pub suspicious_autoruns: usize,
    pub active_connections: usize,
    pub suspicious_connections: usize,
    pub quarantined_count: usize,
    pub realtime_shield_active: bool,
    pub ransomware_shield_active: bool,
    pub groq_configured: bool,
    pub threat_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceConsumer {
    pub name: String,
    pub pid: u32,
    pub instance_count: usize,
    pub cpu_usage: f32,
    pub memory_bytes: u64,
    pub memory_percent: f32,
    pub exe_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemResourceStats {
    pub cpu_brand: String,
    pub cpu_cores: usize,
    pub global_cpu_usage: f32,
    pub total_memory_bytes: u64,
    pub used_memory_bytes: u64,
    pub memory_usage_percent: f32,
    pub total_swap_bytes: u64,
    pub used_swap_bytes: u64,
    pub uptime_seconds: u64,
    pub total_processes: usize,
    pub top_memory_apps: Vec<ResourceConsumer>,
    pub top_cpu_apps: Vec<ResourceConsumer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceInspectionReport {
    pub file_path: String,
    pub file_name: String,
    pub file_size_bytes: u64,
    pub sha256: String,
    pub file_format: String,
    pub entropy: f32,
    pub is_packed_or_encrypted: bool,
    pub risk_score: u32,
    pub verdict: String,
    pub suspicious_apis: Vec<String>,
    pub extracted_urls_and_ips: Vec<String>,
    pub decoded_payloads: Vec<String>,
    pub desourced_preview: String,
    pub groq_analysis: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedFolderStatus {
    pub path: String,
    pub label: String,
    pub exists: bool,
    pub canary_intact: bool,
    pub canary_path: String,
    pub suspicious_files_found: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareStatus {
    pub shield_enabled: bool,
    pub canary_guard_active: bool,
    pub vss_shadow_guard_active: bool,
    pub protected_folders: Vec<ProtectedFolderStatus>,
    pub alerts: Vec<Threat>,
    pub last_checked: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeEvent {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub target: String,
    pub detail: String,
    pub status: String, // "Clean", "Flagged", "Blocked"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeStatus {
    pub enabled: bool,
    pub events_inspected: usize,
    pub threats_flagged: usize,
    pub recent_events: Vec<RealtimeEvent>,
    pub active_threats: Vec<Threat>,
}
