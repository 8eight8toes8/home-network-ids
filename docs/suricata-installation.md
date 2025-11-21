# Suricata IDS Installation on WSL2

## Table of Contents
1. [WSL2 Environment Preparation](#wsl2-environment-preparation)
2. [Suricata Installation](#suricata-installation)
3. [Network Interface Configuration](#network-interface-configuration)
4. [Rule Management Setup](#rule-management-setup)
5. [Performance Tuning](#performance-tuning)
6. [Logging Configuration](#logging-configuration)

---

## WSL2 Environment Preparation

### Enable WSL2 on Windows 11

1. **Enable WSL Feature**
   ```powershell
   # Run PowerShell as Administrator
   wsl --install

   # Or manually enable features
   dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
   dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
   ```

2. **Set WSL2 as Default**
   ```powershell
   wsl --set-default-version 2
   ```

3. **Install Ubuntu 22.04**
   ```powershell
   wsl --install -d Ubuntu-22.04
   ```

4. **Verify WSL2 Installation**
   ```powershell
   wsl -l -v
   # Should show VERSION 2 for Ubuntu
   ```

### Update Ubuntu System

```bash
sudo apt update && sudo apt upgrade -y
sudo apt dist-upgrade -y
```

### Install Build Dependencies

```bash
sudo apt install -y     libpcre3 libpcre3-dev     build-essential autoconf automake libtool     libpcap-dev libnet1-dev libyaml-0-2 libyaml-dev     pkg-config zlib1g zlib1g-dev libcap-ng-dev     libcap-ng0 libmagic-dev libjansson-dev     libjansson4 libgeoip-dev liblz4-dev     rustc cargo python3-yaml
```

---

## Suricata Installation

### Method 1: PPA Installation (Recommended for Beginners)

```bash
# Add Suricata PPA
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update

# Install Suricata
sudo apt install suricata

# Verify installation
suricata --version
```

### Method 2: Source Compilation (Advanced)

```bash
# Download latest stable release
cd /tmp
wget https://www.openinfosecfoundation.org/download/suricata-7.0.2.tar.gz
tar -xvzf suricata-7.0.2.tar.gz
cd suricata-7.0.2

# Configure build
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var     --enable-geoip --enable-lua --enable-rust

# Compile (this takes 10-15 minutes)
make -j $(nproc)

# Install
sudo make install
sudo ldconfig

# Create service user
sudo useradd -r -s /bin/false suricata

# Set up directories
sudo mkdir -p /var/log/suricata
sudo mkdir -p /var/lib/suricata/rules
sudo mkdir -p /etc/suricata/rules
sudo chown -R suricata:suricata /var/log/suricata /var/lib/suricata
```

### Install Suricata-Update (Rule Management)

```bash
sudo apt install python3-pip
sudo pip3 install pyyaml
sudo pip3 install suricata-update

# Or from source
cd /tmp
git clone https://github.com/OISF/suricata-update.git
cd suricata-update
sudo python3 setup.py install
```

---

## Network Interface Configuration

### Configure WSL2 Network Bridge

**On Windows (PowerShell as Admin):**

```powershell
# Create Hyper-V virtual switch for promiscuous mode
New-VMSwitch -Name "WSL-Bridge" -NetAdapterName "Ethernet" -AllowManagementOS $true

# Set promiscuous mode on vEthernet adapter
Get-NetAdapter | Where-Object {$_.Name -like "*WSL*"} | Set-NetAdapterAdvancedProperty -RegistryKeyword "*PriorityVLANTag" -RegistryValue 3
```

### Identify Network Interface in WSL2

```bash
# List network interfaces
ip link show

# Common interfaces:
# - eth0: Primary WSL network adapter
# - eth1: Bridged adapter (if configured)
```

### Enable Promiscuous Mode

```bash
# Enable promiscuous mode on interface
sudo ip link set eth0 promisc on

# Verify
ip link show eth0 | grep PROMISC
# Should show: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP>
```

### Configure Interface in Suricata

Edit `/etc/suricata/suricata.yaml`:

```yaml
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
```

---

## Rule Management Setup

### Initialize Suricata-Update

```bash
# Update rule sources
sudo suricata-update update-sources

# List available sources
sudo suricata-update list-sources

# Enable Emerging Threats Open ruleset
sudo suricata-update enable-source et/open

# Download and install rules
sudo suricata-update
```

### Configure Rule Sources

Create `/etc/suricata/update.yaml`:

```yaml
sources:
  # Emerging Threats Open
  - et/open

  # OISF Trafficid
  - oisf/trafficid

# Rule modifications
modify:
  - action: disable
    rules:
      - group: emerging-dos.rules
      - group: emerging-smtp.rules

# Local rules
local-rules:
  - /etc/suricata/rules/custom.rules
```

### Create Custom Rules

Create `/etc/suricata/rules/custom.rules`:

```bash
# Detect Nmap SYN scan
alert tcp any any -> $HOME_NET any (msg:"CUSTOM Nmap SYN Scan Detected"; flags:S,12; threshold: type both, track by_src, count 10, seconds 60; classtype:attempted-recon; sid:1000001; rev:1;)

# Detect SSH brute force
alert tcp any any -> $HOME_NET 22 (msg:"CUSTOM SSH Brute Force Attempt"; flow:to_server,established; threshold: type both, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000002; rev:1;)

# Detect DNS tunneling
alert dns any any -> any any (msg:"CUSTOM Possible DNS Tunneling"; dns.query; content:"."; pcre:"/^.{50,}/"; threshold: type limit, track by_src, count 1, seconds 60; classtype:policy-violation; sid:1000003; rev:1;)

# Detect large data exfiltration
alert tcp $HOME_NET any -> !$HOME_NET any (msg:"CUSTOM Large Outbound Transfer"; flow:to_server,established; threshold: type threshold, track by_src, count 100, seconds 10; classtype:policy-violation; sid:1000004; rev:1;)
```

### Test Rule Syntax

```bash
# Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml

# Should output: "Configuration provided was successfully loaded. Exiting."
```

---

## Performance Tuning

### Optimize suricata.yaml

Edit `/etc/suricata/suricata.yaml`:

```yaml
# Threading configuration
threading:
  set-cpu-affinity: no
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
    - receive-cpu-set:
        cpu: [ 0-1 ]
    - worker-cpu-set:
        cpu: [ 2-3 ]
  detect-thread-ratio: 1.5

# Performance tuning
max-pending-packets: 2048
default-packet-size: 1514
runmode: workers

# Stream configuration
stream:
  memcap: 128mb
  checksum-validation: yes
  inline: no
  reassembly:
    memcap: 256mb
    depth: 1mb
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560
```

### Memory and CPU Limits

```bash
# Set memory cap in systemd service
sudo systemctl edit suricata

# Add:
[Service]
MemoryLimit=2G
CPUQuota=50%
```

### Threshold Configuration

Create `/etc/suricata/threshold.config`:

```bash
# Suppress noisy rules
suppress gen_id 1, sig_id 2100498  # GPL ICMP_INFO PING
suppress gen_id 1, sig_id 2013028  # ET POLICY HTTP traffic on port 443

# Rate limit alerts
threshold gen_id 1, sig_id 2001219, type limit, track by_src, count 1, seconds 3600

# Event filter for common false positives
event_filter gen_id 1, sig_id 2010935, type threshold, track by_src, count 10, seconds 60
```

---

## Logging Configuration

### EVE JSON Output

Edit `/etc/suricata/suricata.yaml`:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
            metadata: yes
            http-body: yes
            http-body-printable: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: yes
            force-hash: [md5, sha256]
        - flow
        - netflow
        - stats:
            totals: yes
            threads: yes
```

### Log Rotation

Create `/etc/logrotate.d/suricata`:

```bash
/var/log/suricata/*.log /var/log/suricata/*.json {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /bin/kill -HUP $(cat /var/run/suricata.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
```

### Fast Log for Quick Analysis

Enable in `suricata.yaml`:

```yaml
outputs:
  - fast:
      enabled: yes
      filename: /var/log/suricata/fast.log
      append: yes
```

---

## Running Suricata

### Manual Start (Testing)

```bash
# Run in foreground with verbose output
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -v

# Run in daemon mode
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -D
```

### Systemd Service

Create `/etc/systemd/system/suricata.service`:

```ini
[Unit]
Description=Suricata Intrusion Detection Service
After=network.target

[Service]
Type=simple
User=suricata
Group=suricata
ExecStartPre=/usr/bin/suricata -c /etc/suricata/suricata.yaml -T
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --af-packet -D
ExecReload=/bin/kill -USR2 $MAINPID
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl status suricata
```

---

## Monitoring and Validation

### Real-Time Alert Monitoring

```bash
# Watch alerts as they come in
sudo tail -f /var/log/suricata/fast.log

# JSON formatted alerts
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

### Performance Statistics

```bash
# Check Suricata stats
sudo suricatasc -c "dump-counters"

# Monitor packet drops
sudo suricatasc -c "pcap-current"
```

### Test Detection

```bash
# Generate test alert (EICAR test string over HTTP)
curl http://testmyids.com

# Check if alert triggered
sudo grep "EICAR" /var/log/suricata/fast.log
```

---

## Troubleshooting

### Suricata Won't Start

```bash
# Check configuration
sudo suricata -T -c /etc/suricata/suricata.yaml

# Check logs
sudo journalctl -u suricata -n 50

# Verify permissions
sudo chown -R suricata:suricata /var/log/suricata
```

### No Packets Captured

```bash
# Verify interface is up
ip link show eth0

# Check promiscuous mode
ip link show eth0 | grep PROMISC

# Test packet capture
sudo tcpdump -i eth0 -c 10
```

### High CPU Usage

```bash
# Reduce worker threads in suricata.yaml
# Disable unused protocol analyzers
# Tune rule set (disable verbose rules)
```

---

## Additional Resources

- [Suricata User Guide](https://suricata.readthedocs.io/)
- [Rule Management](https://suricata.readthedocs.io/en/latest/rule-management/suricata-update.html)
- [Performance Tuning](https://suricata.readthedocs.io/en/latest/performance/tuning.html)
- [WSL2 Networking](https://docs.microsoft.com/en-us/windows/wsl/networking)

---

*Last Updated: November 2025*
