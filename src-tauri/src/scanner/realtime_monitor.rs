use std::collections::HashSet;
use chrono::Local;
use uuid::Uuid;

use super::autorun_scanner::AutorunScanner;
use super::network_scanner::NetworkScanner;
use super::process_scanner::ProcessScanner;
use super::ransomware_guard::RansomwareGuard;
use super::source_inspector::SourceInspector;
use super::types::{RealtimeEvent, RealtimeStatus, Threat};

pub struct RealtimeMonitorState {
    pub enabled: bool,
    pub known_pids: HashSet<u32>,
    pub events_inspected: usize,
    pub recent_events: Vec<RealtimeEvent>,
    pub active_threats: Vec<Threat>,
}

impl Default for RealtimeMonitorState {
    fn default() -> Self {
        Self::new()
    }
}

impl RealtimeMonitorState {
    pub fn new() -> Self {
        Self {
            enabled: true,
            known_pids: HashSet::new(),
            events_inspected: 0,
            recent_events: Vec::new(),
            active_threats: Vec::new(),
        }
    }

    pub fn push_event(&mut self, event_type: &str, target: &str, detail: &str, status: &str) {
        self.events_inspected += 1;
        self.recent_events.insert(
            0,
            RealtimeEvent {
                id: Uuid::new_v4().to_string(),
                timestamp: Local::now().format("%H:%M:%S").to_string(),
                event_type: event_type.to_string(),
                target: target.to_string(),
                detail: detail.to_string(),
                status: status.to_string(),
            },
        );
        if self.recent_events.len() > 60 {
            self.recent_events.truncate(60);
        }
    }

    pub fn poll_tick(&mut self) -> RealtimeStatus {
        if !self.enabled {
            return RealtimeStatus {
                enabled: false,
                events_inspected: self.events_inspected,
                threats_flagged: self.active_threats.len(),
                recent_events: self.recent_events.clone(),
                active_threats: self.active_threats.clone(),
            };
        }

        let mut all_threats = Vec::new();

        // 1. Check live processes & newly spawned processes
        let (procs, proc_threats) = ProcessScanner::scan_processes();
        all_threats.extend(proc_threats);

        let is_first_seed = self.known_pids.is_empty();
        let mut current_pids = HashSet::new();

        for p in &procs {
            current_pids.insert(p.pid);
            if !is_first_seed && !self.known_pids.contains(&p.pid) {
                // Newly spawned process! Perform instant de-source & path verification
                let mut status = if p.is_suspicious { "Flagged" } else { "Clean" };
                let mut detail = p
                    .suspicion_reason
                    .clone()
                    .unwrap_or_else(|| format!("Verified spawn ({})", if p.exe_path.is_empty() { "System" } else { &p.exe_path }));

                if !p.exe_path.is_empty() {
                    if let Ok(report) = SourceInspector::inspect_file(&p.exe_path) {
                        if report.risk_score >= 55 {
                            status = "Flagged";
                            detail = format!(
                                "De-source alert: Risk {}/100, Entropy {:.2}",
                                report.risk_score, report.entropy
                            );
                        } else {
                            detail = format!(
                                "Source verified · SHA-256 {}… · Entropy {:.2}",
                                &report.sha256[..8.min(report.sha256.len())],
                                report.entropy
                            );
                        }
                    }
                }

                self.push_event(
                    "Process Spawn",
                    &format!("{} (PID {})", p.name, p.pid),
                    &detail,
                    status,
                );
            }
        }

        if is_first_seed {
            self.push_event(
                "Process Guard",
                &format!("{} active processes", procs.len()),
                "Initial real-time process & memory baseline established",
                "Clean",
            );
        }
        self.known_pids = current_pids;

        // 2. Check Network Sockets
        let (sockets, sock_threats) = NetworkScanner::scan_network_sockets();
        if !sock_threats.is_empty() {
            for st in &sock_threats {
                self.push_event(
                    "Network Guard",
                    &st.name,
                    &st.description,
                    "Flagged",
                );
            }
        } else if self.events_inspected < 5 {
            self.push_event(
                "Network Guard",
                &format!("{} active sockets", sockets.len()),
                "All outbound TCP/UDP endpoints verified against C2 port rules",
                "Clean",
            );
        }
        all_threats.extend(sock_threats);

        // 3. Check Autoruns
        let (autoruns, auto_threats) = AutorunScanner::scan_autoruns();
        if !auto_threats.is_empty() {
            for at in &auto_threats {
                self.push_event(
                    "Startup Guard",
                    &at.name,
                    &at.description,
                    "Flagged",
                );
            }
        } else if self.events_inspected < 6 {
            self.push_event(
                "Startup Guard",
                &format!("{} registry/startup hooks", autoruns.len()),
                "Registry Run keys and startup folders verified",
                "Clean",
            );
        }
        all_threats.extend(auto_threats);

        // 4. Check Ransomware Canaries
        let r_status = RansomwareGuard::check_status(true);
        if !r_status.alerts.is_empty() {
            for alert in &r_status.alerts {
                self.push_event(
                    "Ransomware Shield",
                    &alert.name,
                    &alert.description,
                    "Flagged",
                );
            }
            all_threats.extend(r_status.alerts);
        } else if self.events_inspected < 8 {
            self.push_event(
                "Ransomware Canary",
                &format!("{} protected folders", r_status.protected_folders.len()),
                "All SHA-256 decoy canary traps intact; no VSS tampering",
                "Clean",
            );
        }

        self.active_threats = all_threats;

        RealtimeStatus {
            enabled: self.enabled,
            events_inspected: self.events_inspected,
            threats_flagged: self.active_threats.len(),
            recent_events: self.recent_events.clone(),
            active_threats: self.active_threats.clone(),
        }
    }
}
