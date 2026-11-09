use std::collections::HashMap;
use sysinfo::{ProcessesToUpdate, System};
use chrono::Utc;
use uuid::Uuid;
use super::types::{MonitoredProcess, ResourceConsumer, SystemResourceStats, Threat, ThreatCategory, ThreatSeverity};

pub struct ProcessScanner;

impl ProcessScanner {
    pub fn scan_processes() -> (Vec<MonitoredProcess>, Vec<Threat>) {
        let mut sys = System::new_all();
        sys.refresh_processes(ProcessesToUpdate::All, true);

        let mut monitored_list = Vec::new();
        let mut threats = Vec::new();

        let known_system_executables = [
            "svchost.exe",
            "csrss.exe",
            "lsass.exe",
            "services.exe",
            "smss.exe",
            "wininit.exe",
            "winlogon.exe",
            "taskhostw.exe",
            "dwm.exe",
            "sihost.exe",
        ];

        let spyware_signatures = [
            ("keylog", ThreatCategory::Keylogger, ThreatSeverity::Critical, "Potential Keylogger engine capturing keystrokes"),
            ("keyspy", ThreatCategory::Keylogger, ThreatSeverity::Critical, "Known Keystroke monitor signature"),
            ("hookkey", ThreatCategory::Keylogger, ThreatSeverity::Critical, "Low-level keyboard hook monitor"),
            ("redline", ThreatCategory::InfoStealer, ThreatSeverity::Critical, "RedLine Infostealer variant targeting credentials"),
            ("vidar", ThreatCategory::InfoStealer, ThreatSeverity::Critical, "Vidar credential and crypto-wallet harvester"),
            ("agenttesla", ThreatCategory::InfoStealer, ThreatSeverity::Critical, "AgentTesla spyware trojan"),
            ("asyncrat", ThreatCategory::RemoteAccessTrojan, ThreatSeverity::Critical, "AsyncRAT remote administration spyware"),
            ("quasarrat", ThreatCategory::RemoteAccessTrojan, ThreatSeverity::Critical, "QuasarRAT unauthorized remote access tool"),
            ("njrat", ThreatCategory::RemoteAccessTrojan, ThreatSeverity::Critical, "NjRAT remote access backdoor"),
            ("remcos", ThreatCategory::RemoteAccessTrojan, ThreatSeverity::Critical, "Remcos RAT surveillance utility"),
            ("darkcomet", ThreatCategory::RemoteAccessTrojan, ThreatSeverity::Critical, "DarkComet RAT spy engine"),
            ("tokengrabber", ThreatCategory::InfoStealer, ThreatSeverity::High, "Discord/Browser session token grabber"),
            ("clipbank", ThreatCategory::InfoStealer, ThreatSeverity::High, "Cryptocurrency clipboard hijacker"),
            ("xmrig", ThreatCategory::SuspiciousDropper, ThreatSeverity::High, "Unauthorized background crypto miner"),
        ];

        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let name_os = process.name().to_string_lossy();
            let name = name_os.to_lowercase();
            let exe_path_buf = process.exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
            let exe_path_lower = exe_path_buf.to_lowercase();
            let parent_pid_u32 = process.parent().map(|p| p.as_u32());
            let cpu_usage = process.cpu_usage();
            let memory_bytes = process.memory();

            let mut is_suspicious = false;
            let mut suspicion_reasons = Vec::new();

            // 1. Check System Binary Masquerading
            for sys_bin in &known_system_executables {
                if name == *sys_bin {
                    if !exe_path_lower.is_empty() {
                        let is_legit_system_path = exe_path_lower.contains("c:\\windows\\system32")
                            || exe_path_lower.contains("c:\\windows\\syswow64")
                            || (name == "explorer.exe" && exe_path_lower.contains("c:\\windows"));
                        
                        if !is_legit_system_path {
                            is_suspicious = true;
                            let reason = format!(
                                "Masquerading system process: '{}' running from unauthorized directory '{}'",
                                name, exe_path_buf
                            );
                            suspicion_reasons.push(reason.clone());

                            threats.push(Threat {
                                id: Uuid::new_v4().to_string(),
                                name: format!("Masquerading {}", name),
                                category: ThreatCategory::RemoteAccessTrojan,
                                severity: ThreatSeverity::Critical,
                                description: reason,
                                file_path: Some(exe_path_buf.clone()),
                                pid: Some(pid_u32),
                                registry_key: None,
                                remote_addr: None,
                                detected_at: Utc::now().to_rfc3339(),
                                status: "Active".to_string(),
                                recommendation: "Terminate process immediately and quarantine executable".to_string(),
                            });
                        }
                    }
                }
            }

            // 2. Check Suspicious Drop Directories (Temp, Public, INetCache)
            let is_in_temp = exe_path_lower.contains("\\appdata\\local\\temp\\")
                || exe_path_lower.contains("\\appdata\\roaming\\microsoft\\windows\\templates\\")
                || exe_path_lower.contains("c:\\users\\public\\");
            
            if is_in_temp && !name.contains("installer") && !name.contains("update") && !name.contains("setup") {
                is_suspicious = true;
                let reason = format!("Process executing directly from temporary/public drop folder: {}", exe_path_buf);
                suspicion_reasons.push(reason.clone());

                threats.push(Threat {
                    id: Uuid::new_v4().to_string(),
                    name: format!("Suspicious Temp Executable ({})", name),
                    category: ThreatCategory::SuspiciousDropper,
                    severity: ThreatSeverity::High,
                    description: reason,
                    file_path: Some(exe_path_buf.clone()),
                    pid: Some(pid_u32),
                    registry_key: None,
                    remote_addr: None,
                    detected_at: Utc::now().to_rfc3339(),
                    status: "Active".to_string(),
                    recommendation: "Inspect file origin and quarantine if unrecognized".to_string(),
                });
            }

            // 3. Check Double Extensions (e.g. invoice.pdf.exe)
            let double_exts = [".pdf.exe", ".jpg.exe", ".png.exe", ".docx.exe", ".xlsx.exe", ".txt.exe", ".zip.exe"];
            for ext in &double_exts {
                if name.ends_with(ext) {
                    is_suspicious = true;
                    let reason = format!("Double extension spoofing detected in process name '{}'", name);
                    suspicion_reasons.push(reason.clone());

                    threats.push(Threat {
                        id: Uuid::new_v4().to_string(),
                        name: "Deceptive File Extension Phishing/Dropper".to_string(),
                        category: ThreatCategory::SuspiciousDropper,
                        severity: ThreatSeverity::Critical,
                        description: reason,
                        file_path: Some(exe_path_buf.clone()),
                        pid: Some(pid_u32),
                        registry_key: None,
                        remote_addr: None,
                        detected_at: Utc::now().to_rfc3339(),
                        status: "Active".to_string(),
                        recommendation: "Kill process and quarantine payload immediately".to_string(),
                    });
                }
            }

            // 4. Check Spyware / Keylogger signatures in process name or binary path
            for (sig, category, severity, desc) in &spyware_signatures {
                if name.contains(sig) || exe_path_lower.contains(sig) {
                    is_suspicious = true;
                    let reason = format!("{}: matched signature '{}' in {}", desc, sig, name);
                    suspicion_reasons.push(reason.clone());

                    threats.push(Threat {
                        id: Uuid::new_v4().to_string(),
                        name: format!("Spyware Signature Match: {}", sig),
                        category: category.clone(),
                        severity: severity.clone(),
                        description: reason,
                        file_path: Some(exe_path_buf.clone()),
                        pid: Some(pid_u32),
                        registry_key: None,
                        remote_addr: None,
                        detected_at: Utc::now().to_rfc3339(),
                        status: "Active".to_string(),
                        recommendation: "Terminate process immediately and run deep system clean".to_string(),
                    });
                }
            }

            // 5. Check Suspicious Command Line Arguments
            let cmdline = process.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect::<Vec<_>>().join(" ");
            let cmdline_lower = cmdline.to_lowercase();
            if cmdline_lower.contains("-w hidden") 
                || cmdline_lower.contains("-windowstyle hidden")
                || cmdline_lower.contains("certutil -urlcache")
                || cmdline_lower.contains("vssadmin delete shadows") 
            {
                is_suspicious = true;
                let reason = format!("Process using stealth / evasion command-line arguments: {}", cmdline);
                suspicion_reasons.push(reason.clone());

                threats.push(Threat {
                    id: Uuid::new_v4().to_string(),
                    name: "Stealth Evasion / Download Cradle".to_string(),
                    category: ThreatCategory::SuspiciousDropper,
                    severity: ThreatSeverity::High,
                    description: reason,
                    file_path: Some(exe_path_buf.clone()),
                    pid: Some(pid_u32),
                    registry_key: None,
                    remote_addr: None,
                    detected_at: Utc::now().to_rfc3339(),
                    status: "Active".to_string(),
                    recommendation: "Review parent process and terminate suspicious execution".to_string(),
                });
            }

            let reason_opt = if !suspicion_reasons.is_empty() {
                Some(suspicion_reasons.join("; "))
            } else {
                None
            };

            monitored_list.push(MonitoredProcess {
                pid: pid_u32,
                name: name_os.to_string(),
                exe_path: exe_path_buf,
                cpu_usage,
                memory_bytes,
                is_suspicious,
                suspicion_reason: reason_opt,
                parent_pid: parent_pid_u32,
            });
        }

        monitored_list.sort_by(|a, b| {
            b.is_suspicious.cmp(&a.is_suspicious)
                .then_with(|| b.memory_bytes.cmp(&a.memory_bytes))
        });

        (monitored_list, threats)
    }

    pub fn terminate_process(pid: u32) -> Result<(), String> {
        let mut sys = System::new_all();
        sys.refresh_processes(ProcessesToUpdate::All, true);

        if let Some(process) = sys.process(sysinfo::Pid::from_u32(pid)) {
            if process.kill() {
                Ok(())
            } else {
                let output = std::process::Command::new("taskkill")
                    .args(["/F", "/PID", &pid.to_string()])
                    .output()
                    .map_err(|e| format!("Failed to invoke taskkill: {}", e))?;

                if output.status.success() {
                    Ok(())
                } else {
                    Err(String::from_utf8_lossy(&output.stderr).to_string())
                }
            }
        } else {
            let output = std::process::Command::new("taskkill")
                .args(["/F", "/PID", &pid.to_string()])
                .output()
                .map_err(|e| format!("Failed to invoke taskkill: {}", e))?;

            if output.status.success() {
                Ok(())
            } else {
                Err("Process PID not found or already terminated".to_string())
            }
        }
    }

    pub fn collect_resource_stats(sys: &mut System) -> SystemResourceStats {
        sys.refresh_cpu_all();
        sys.refresh_memory();
        sys.refresh_processes(ProcessesToUpdate::All, true);

        let cpus = sys.cpus();
        let cpu_cores = cpus.len().max(1);
        let cpu_brand = cpus
            .first()
            .map(|c| c.brand().trim().to_string())
            .unwrap_or_else(|| "System Processor".to_string());
        let global_cpu_usage = sys.global_cpu_usage();

        let total_memory_bytes = sys.total_memory();
        let used_memory_bytes = sys.used_memory();
        let memory_usage_percent = if total_memory_bytes > 0 {
            ((used_memory_bytes as f64 / total_memory_bytes as f64) * 100.0) as f32
        } else {
            0.0
        };

        let total_swap_bytes = sys.total_swap();
        let used_swap_bytes = sys.used_swap();
        let uptime_seconds = System::uptime();
        let total_processes = sys.processes().len();

        let mut grouped: HashMap<String, (String, u32, u64, usize, f32, u64, String)> = HashMap::new();

        for (pid, proc) in sys.processes() {
            let pid_u32 = pid.as_u32();
            if pid_u32 == 0 {
                continue;
            }
            let display_name = proc.name().to_string_lossy().to_string();
            let key = display_name.to_lowercase();
            let mem = proc.memory();
            let cpu = proc.cpu_usage() / (cpu_cores as f32);
            let path = proc.exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();

            let entry = grouped.entry(key).or_insert((
                display_name.clone(),
                pid_u32,
                mem,
                0,
                0.0,
                0,
                path.clone(),
            ));

            entry.3 += 1;
            entry.4 += cpu;
            entry.5 += mem;
            if mem > entry.2 {
                entry.1 = pid_u32;
                entry.2 = mem;
                if !path.is_empty() {
                    entry.6 = path;
                }
            }
        }

        let all_consumers: Vec<ResourceConsumer> = grouped
            .into_values()
            .map(|(name, pid, _, instance_count, cpu_usage, memory_bytes, exe_path)| {
                let memory_percent = if total_memory_bytes > 0 {
                    ((memory_bytes as f64 / total_memory_bytes as f64) * 100.0) as f32
                } else {
                    0.0
                };
                ResourceConsumer {
                    name,
                    pid,
                    instance_count,
                    cpu_usage,
                    memory_bytes,
                    memory_percent,
                    exe_path,
                }
            })
            .collect();

        let mut top_memory_apps = all_consumers.clone();
        top_memory_apps.sort_by(|a, b| b.memory_bytes.cmp(&a.memory_bytes));
        top_memory_apps.truncate(12);

        let mut top_cpu_apps = all_consumers;
        top_cpu_apps.sort_by(|a, b| {
            b.cpu_usage
                .partial_cmp(&a.cpu_usage)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.memory_bytes.cmp(&a.memory_bytes))
        });
        top_cpu_apps.truncate(12);

        SystemResourceStats {
            cpu_brand,
            cpu_cores,
            global_cpu_usage,
            total_memory_bytes,
            used_memory_bytes,
            memory_usage_percent,
            total_swap_bytes,
            used_swap_bytes,
            uptime_seconds,
            total_processes,
            top_memory_apps,
            top_cpu_apps,
        }
    }
}
