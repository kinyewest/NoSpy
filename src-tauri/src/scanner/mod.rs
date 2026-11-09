pub mod types;
pub mod process_scanner;
pub mod autorun_scanner;
pub mod network_scanner;
pub mod file_scanner;
pub mod quarantine_manager;
pub mod source_inspector;
pub mod ransomware_guard;
pub mod groq_analyzer;
pub mod realtime_monitor;

use std::time::Instant;
use chrono::Utc;
use uuid::Uuid;

use types::{ScanResult, SystemSummary};
use process_scanner::ProcessScanner;
use autorun_scanner::AutorunScanner;
use network_scanner::NetworkScanner;
use file_scanner::FileScanner;
use quarantine_manager::QuarantineManager;
use source_inspector::SourceInspector;
use ransomware_guard::RansomwareGuard;
use groq_analyzer::GroqAnalyzer;

pub struct ScannerEngine;

impl ScannerEngine {
    pub fn get_summary(realtime_shield: bool, ransomware_shield: bool) -> SystemSummary {
        let (procs, proc_threats) = ProcessScanner::scan_processes();
        let (autoruns, auto_threats) = AutorunScanner::scan_autoruns();
        let (sockets, sock_threats) = NetworkScanner::scan_network_sockets();
        let q_items = QuarantineManager::list_quarantined();

        let total_threats = proc_threats.len() + auto_threats.len() + sock_threats.len();
        let threat_level = if total_threats == 0 {
            "SECURE".to_string()
        } else if total_threats < 3 {
            "CAUTION".to_string()
        } else {
            "CRITICAL".to_string()
        };

        SystemSummary {
            total_processes: procs.len(),
            suspicious_processes: proc_threats.len(),
            total_autoruns: autoruns.len(),
            suspicious_autoruns: auto_threats.len(),
            active_connections: sockets.len(),
            suspicious_connections: sock_threats.len(),
            quarantined_count: q_items.len(),
            realtime_shield_active: realtime_shield,
            ransomware_shield_active: ransomware_shield,
            groq_configured: GroqAnalyzer::is_configured(),
            threat_level,
        }
    }

    pub fn quick_scan() -> ScanResult {
        let start = Instant::now();
        let mut all_threats = Vec::new();

        // 1. Scan Processes
        let (procs, proc_threats) = ProcessScanner::scan_processes();
        all_threats.extend(proc_threats);

        // 2. Scan Autoruns
        let (autoruns, auto_threats) = AutorunScanner::scan_autoruns();
        all_threats.extend(auto_threats);

        // 3. Scan Network Sockets
        let (sockets, net_threats) = NetworkScanner::scan_network_sockets();
        all_threats.extend(net_threats);

        // 4. Fast temp file check (first 200 files)
        let (file_count, file_threats) = FileScanner::scan_threat_directories(200);
        all_threats.extend(file_threats);

        // 5. De-source & static binary/script inspection on active processes
        let (desourced_count, _, source_threats) = SourceInspector::scan_all_active_sources(18);
        all_threats.extend(source_threats);

        // 6. Ransomware canary & folder check
        let r_status = RansomwareGuard::check_status(true);
        all_threats.extend(r_status.alerts);

        let total_items = procs.len() + autoruns.len() + sockets.len() + file_count + desourced_count;
        let groq_ai_summary = GroqAnalyzer::analyze_scan_threats(&all_threats, total_items, desourced_count);

        let elapsed = start.elapsed().as_millis() as u64;

        let system_status = if all_threats.is_empty() {
            "SECURE".to_string()
        } else if all_threats.iter().any(|t| t.severity == types::ThreatSeverity::Critical) {
            "CRITICAL".to_string()
        } else {
            "WARNING".to_string()
        };

        ScanResult {
            scan_id: Uuid::new_v4().to_string(),
            scan_type: "Quick Scan + De-Source".to_string(),
            total_scanned: total_items,
            threats: all_threats,
            elapsed_ms: elapsed,
            timestamp: Utc::now().to_rfc3339(),
            system_status,
            groq_ai_summary,
            desourced_count,
        }
    }

    pub fn deep_scan() -> ScanResult {
        let start = Instant::now();
        let mut all_threats = Vec::new();

        // 1. Scan Processes
        let (procs, proc_threats) = ProcessScanner::scan_processes();
        all_threats.extend(proc_threats);

        // 2. Scan Autoruns
        let (autoruns, auto_threats) = AutorunScanner::scan_autoruns();
        all_threats.extend(auto_threats);

        // 3. Scan Network Sockets
        let (sockets, net_threats) = NetworkScanner::scan_network_sockets();
        all_threats.extend(net_threats);

        // 4. Deep file scan (up to 3000 files in Temp, INetCache, Templates)
        let (file_count, file_threats) = FileScanner::scan_threat_directories(3000);
        all_threats.extend(file_threats);

        // 5. Deep De-source & binary entropy/API inspection across up to 45 processes
        let (desourced_count, _, source_threats) = SourceInspector::scan_all_active_sources(45);
        all_threats.extend(source_threats);

        // 6. Ransomware canary & behavioral check
        let r_status = RansomwareGuard::check_status(true);
        all_threats.extend(r_status.alerts);

        let total_items = procs.len() + autoruns.len() + sockets.len() + file_count + desourced_count;
        let groq_ai_summary = GroqAnalyzer::analyze_scan_threats(&all_threats, total_items, desourced_count);

        let elapsed = start.elapsed().as_millis() as u64;

        let system_status = if all_threats.is_empty() {
            "SECURE".to_string()
        } else if all_threats.iter().any(|t| t.severity == types::ThreatSeverity::Critical) {
            "CRITICAL".to_string()
        } else {
            "WARNING".to_string()
        };

        ScanResult {
            scan_id: Uuid::new_v4().to_string(),
            scan_type: "Deep System + De-Source Scan".to_string(),
            total_scanned: total_items,
            threats: all_threats,
            elapsed_ms: elapsed,
            timestamp: Utc::now().to_rfc3339(),
            system_status,
            groq_ai_summary,
            desourced_count,
        }
    }
}
