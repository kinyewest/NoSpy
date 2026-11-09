use std::collections::HashMap;
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use sysinfo::{ProcessesToUpdate, System};
use chrono::Utc;
use uuid::Uuid;
use super::types::{NetworkSocketEntry, Threat, ThreatCategory, ThreatSeverity};

pub struct NetworkScanner;

impl NetworkScanner {
    pub fn scan_network_sockets() -> (Vec<NetworkSocketEntry>, Vec<Threat>) {
        let mut sys = System::new_all();
        sys.refresh_processes(ProcessesToUpdate::All, true);

        let mut pid_map = HashMap::new();
        for (pid, proc) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let name = proc.name().to_string_lossy().to_string();
            let path = proc.exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
            pid_map.insert(pid_u32, (name, path));
        }

        let mut sockets_list = Vec::new();
        let mut threats = Vec::new();

        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

        let suspicious_c2_ports = [
            (4444, "Metasploit / Reverse Shell Default C2 Port"),
            (1604, "DarkComet RAT Default Listening Port"),
            (1177, "NjRAT Remote Access Trojan Port"),
            (5552, "Spyware / RAT Phoning Home Port"),
            (6666, "IRC Botnet / Spyware Command Port"),
            (7777, "Generic RAT Control Port"),
            (8888, "Unauthorized Proxy / RAT C2 Port"),
            (1337, "Common Backdoor / Elite Port"),
            (3175, "Trojan Backdoor Port"),
            (48101, "Mozi / Mirai Botnet Port"),
        ];

        if let Ok(sockets) = get_sockets_info(af_flags, proto_flags) {
            for si in sockets {
                for pid in si.associated_pids {
                    let (proc_name, proc_path) = pid_map.get(&pid).cloned().unwrap_or_else(|| {
                        ("Unknown".to_string(), "".to_string())
                    });

                    let proc_path_lower = proc_path.to_lowercase();
                    let (protocol, local_addr_str, remote_addr_str, remote_port, state_str) = match &si.protocol_socket_info {
                        ProtocolSocketInfo::Tcp(tcp) => {
                            let loc = format!("{}:{}", tcp.local_addr, tcp.local_port);
                            let rem = format!("{}:{}", tcp.remote_addr, tcp.remote_port);
                            ("TCP", loc, rem, tcp.remote_port, format!("{:?}", tcp.state))
                        }
                        ProtocolSocketInfo::Udp(udp) => {
                            let loc = format!("{}:{}", udp.local_addr, udp.local_port);
                            ("UDP", loc, "*:*".to_string(), 0, "OPEN".to_string())
                        }
                    };

                    let mut is_suspicious = false;
                    let mut risk_reason = None;

                    for (port, desc) in &suspicious_c2_ports {
                        if remote_port == *port {
                            is_suspicious = true;
                            let reason = format!("Connection established to known spy C2 port {} ({})", port, desc);
                            risk_reason = Some(reason.clone());

                            threats.push(Threat {
                                id: Uuid::new_v4().to_string(),
                                name: format!("Potential RAT / C2 Beacon: {}", desc),
                                category: ThreatCategory::NetworkSpy,
                                severity: ThreatSeverity::Critical,
                                description: format!(
                                    "Process '{}' (PID {}) connected to suspicious remote address {} on port {}",
                                    proc_name, pid, remote_addr_str, port
                                ),
                                file_path: if proc_path.is_empty() { None } else { Some(proc_path.clone()) },
                                pid: Some(pid),
                                registry_key: None,
                                remote_addr: Some(remote_addr_str.clone()),
                                detected_at: Utc::now().to_rfc3339(),
                                status: "Active".to_string(),
                                recommendation: "Terminate process and block outbound socket".to_string(),
                            });
                        }
                    }

                    let is_in_temp = proc_path_lower.contains("\\temp\\") || proc_path_lower.contains("\\appdata\\local\\temp\\");
                    if is_in_temp && remote_port != 0 && remote_port != 80 && remote_port != 443 {
                        is_suspicious = true;
                        let reason = format!("Temp directory binary phoning home to external port {}", remote_port);
                        risk_reason = Some(reason.clone());

                        threats.push(Threat {
                            id: Uuid::new_v4().to_string(),
                            name: "Temp Binary Outbound Data Exfiltration".to_string(),
                            category: ThreatCategory::NetworkSpy,
                            severity: ThreatSeverity::High,
                            description: format!(
                                "Executable '{}' in temp folder is maintaining socket to {}",
                                proc_name, remote_addr_str
                            ),
                            file_path: Some(proc_path.clone()),
                            pid: Some(pid),
                            registry_key: None,
                            remote_addr: Some(remote_addr_str.clone()),
                            detected_at: Utc::now().to_rfc3339(),
                            status: "Active".to_string(),
                            recommendation: "Investigate target IP and terminate binary".to_string(),
                        });
                    }

                    sockets_list.push(NetworkSocketEntry {
                        pid,
                        process_name: proc_name,
                        protocol: protocol.to_string(),
                        local_addr: local_addr_str,
                        remote_addr: remote_addr_str,
                        state: state_str,
                        is_suspicious,
                        risk_reason,
                    });
                }
            }
        }

        sockets_list.sort_by(|a, b| b.is_suspicious.cmp(&a.is_suspicious));

        (sockets_list, threats)
    }
}
