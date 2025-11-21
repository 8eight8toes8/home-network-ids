# Home Network Intrusion Detection System (IDS)

[![OpenWrt](https://img.shields.io/badge/OpenWrt-Router-00B5E2?logo=openwrt&logoColor=white)](https://openwrt.org/)
[![Suricata](https://img.shields.io/badge/Suricata-IDS-FF6600?logo=suricata&logoColor=white)](https://suricata.io/)
[![WSL2](https://img.shields.io/badge/WSL2-Ubuntu-FCC624?logo=linux&logoColor=black)](https://docs.microsoft.com/en-us/windows/wsl/)

> **Professional home network security implementation featuring OpenWrt firewall configuration and Suricata IDS deployment on WSL2**

## 📋 Project Overview

This repository documents the deployment of a multi-layered network intrusion detection system for home lab environments. The implementation combines OpenWrt router-level firewall controls with Suricata IDS running on WSL2 for comprehensive network monitoring and threat detection.

**Key Objectives:**
- Implement enterprise-grade network security in home lab environment
- Monitor and analyze network traffic for suspicious activity
- Document reproducible security architecture
- Practice SOC analyst skills with real-world traffic analysis

---

## 🏗️ Architecture

```
Internet
   │
   ↓
[ISP Modem/Gateway]
   │
   ↓
[OpenWrt Router] ← Firewall Rules, ACLs, Port Mirroring
   │
   ├─→ [Home Network Devices]
   │
   └─→ [WSL2 Ubuntu] ← Suricata IDS Engine
           │
           └─→ Log Analysis & Alerting
```

### Components

1. **OpenWrt Router**
   - Custom firewall ruleset (DMZ, port forwarding, ACLs)
   - Traffic mirroring/SPAN port configuration
   - Network segmentation

2. **Suricata IDS (WSL2)**
   - Real-time packet analysis
   - Signature-based threat detection
   - Protocol anomaly detection
   - EVE JSON logging for SIEM integration

3. **Log Management**
   - EVE JSON output format
   - Integration-ready for Splunk/ELK
   - Custom alert correlation rules

---

## 🛠️ Technical Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Router OS | OpenWrt 23.05+ | Network gateway and traffic control |
| IDS Engine | Suricata 7.x | Network intrusion detection |
| Host Platform | WSL2 (Ubuntu 22.04) | Linux environment on Windows 11 |
| Packet Capture | libpcap / AF_PACKET | Network interface monitoring |
| Rule Management | Emerging Threats Open | Threat signature database |
| Log Format | EVE JSON | Structured logging for analysis |

---

## 📚 Documentation

### Setup Guides

- **[OpenWrt Router Configuration](docs/openwrt-setup.md)**
  - Initial router setup
  - Firewall rule implementation
  - Port mirroring/SPAN configuration
  - DMZ and network segmentation

- **[Suricata IDS Installation](docs/suricata-installation.md)**
  - WSL2 environment preparation
  - Suricata compilation and installation
  - Network interface configuration
  - Rule management setup

- **[Integration & Testing](docs/integration-testing.md)**
  - Traffic flow verification
  - Alert validation
  - Performance tuning
  - False positive reduction

### Configuration Files

```
configs/
├── openwrt/
│   ├── firewall.conf          # OpenWrt firewall rules
│   ├── network.conf           # Network interface config
│   └── dhcp.conf              # DHCP and DNS settings
├── suricata/
│   ├── suricata.yaml          # Main Suricata configuration
│   ├── threshold.config       # Alert thresholds
│   └── custom.rules           # Custom detection rules
└── scripts/
    ├── update-rules.sh        # Automated rule updates
    └── log-rotation.sh        # Log management
```

---

## 🚀 Quick Start

### Prerequisites

- OpenWrt-compatible router (or VM)
- Windows 11 with WSL2 enabled
- Ubuntu 22.04 on WSL2
- Basic networking knowledge

### Installation Steps

1. **Configure OpenWrt Router**
   ```bash
   # SSH into OpenWrt router
   ssh root@192.168.1.1
   
   # Install required packages
   opkg update
   opkg install tcpdump iptables-mod-tee
   ```

2. **Install Suricata on WSL2**
   ```bash
   # Update package list
   sudo apt update && sudo apt upgrade -y
   
   # Install dependencies
   sudo apt install libpcap-dev libpcre3-dev libyaml-dev \
                    libjansson-dev libmagic-dev zlib1g-dev
   
   # Install Suricata
   sudo add-apt-repository ppa:oisf/suricata-stable
   sudo apt install suricata
   ```

3. **Configure Network Monitoring**
   ```bash
   # Enable promiscuous mode on network interface
   sudo ip link set eth0 promisc on
   
   # Start Suricata
   sudo suricata -c /etc/suricata/suricata.yaml -i eth0
   ```

---

## 🔍 Monitoring & Analysis

### Key Detection Capabilities

- **Network Reconnaissance**: Nmap scans, port sweeps, service enumeration
- **Exploit Attempts**: CVE-based signatures, payload detection
- **Protocol Anomalies**: Malformed packets, unusual traffic patterns
- **C2 Communications**: Known malware signatures, beaconing behavior
- **Data Exfiltration**: Large outbound transfers, suspicious destinations

### Log Analysis

Suricata generates EVE JSON logs in `/var/log/suricata/eve.json`:

```bash
# Real-time alert monitoring
tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'

# Alert summary
cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert") | .alert.signature' | sort | uniq -c | sort -rn
```

---

## 📊 Performance Metrics

- **Packet Processing**: ~500 Mbps sustained throughput
- **Alert Latency**: <100ms detection to log
- **False Positive Rate**: <2% after tuning
- **Resource Usage**: ~150MB RAM, 5-10% CPU (idle network)

---

## 🎯 Use Cases

1. **Security Operations Training**
   - Practice alert triage and investigation
   - Learn packet analysis techniques
   - Develop incident response workflows

2. **Threat Research**
   - Analyze malware traffic patterns
   - Test exploit detection capabilities
   - Validate firewall rules

3. **Network Visibility**
   - Monitor home network activity
   - Identify vulnerable devices
   - Detect unauthorized access attempts

---

## 🔧 Troubleshooting

### Common Issues

**Suricata not capturing packets:**
```bash
# Check interface configuration
sudo suricata --list-runmodes

# Verify promiscuous mode
ip link show eth0 | grep PROMISC
```

**High false positive rate:**
- Review `threshold.config` settings
- Disable overly aggressive rules
- Implement IP whitelisting for trusted hosts

**WSL2 network bridge issues:**
- Ensure Hyper-V virtual switch is configured correctly
- Check Windows Defender Firewall rules
- Use `netsh` to verify network adapter status

---

## 📖 Learning Resources

- [Suricata User Guide](https://suricata.readthedocs.io/)
- [OpenWrt Documentation](https://openwrt.org/docs/start)
- [Emerging Threats Rules](https://rules.emergingthreats.net/)
- [SANS SEC503: Intrusion Detection](https://www.sans.org/cyber-security-courses/intrusion-detection-in-depth/)

---

## 🤝 Contributing

This is a personal learning project, but suggestions and improvements are welcome! Feel free to:
- Open issues for questions or problems
- Submit pull requests for documentation improvements
- Share your own IDS configuration experiences

---

## 📝 License

This project documentation is provided as-is for educational purposes. Configuration files are released under MIT License.

---

## 👤 Author

**Jay Henderson**
- Cybersecurity Intern @ MCCoE
- GitHub: [@8eight8toes8](https://github.com/8eight8toes8)
- Email: jhenderson@mccoe.org

---

## 🔖 Project Status

**Current Phase:** Active Development & Documentation

**Completed:**
- ✅ OpenWrt router deployment
- ✅ Suricata IDS installation on WSL2
- ✅ Basic rule configuration
- ✅ Initial testing and validation

**In Progress:**
- 🔄 Advanced rule tuning
- 🔄 SIEM integration (Splunk)
- 🔄 Automated alerting workflows
- 🔄 Comprehensive documentation

**Planned:**
- 📋 Threat intelligence feed integration
- 📋 Custom dashboard creation
- 📋 Automated incident response scripts
- 📋 Network baseline profiling

---

*Last Updated: November 2025*