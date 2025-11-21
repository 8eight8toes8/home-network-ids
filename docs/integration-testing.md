# Integration & Testing Guide

## Table of Contents
1. [Traffic Flow Verification](#traffic-flow-verification)
2. [Alert Validation](#alert-validation)
3. [Performance Testing](#performance-testing)
4. [False Positive Reduction](#false-positive-reduction)
5. [SIEM Integration Testing](#siem-integration-testing)
6. [Incident Response Testing](#incident-response-testing)

---

## Traffic Flow Verification

### End-to-End Connectivity Test

**Step 1: Verify OpenWrt Router Connectivity**

```bash
# From client device
ping 192.168.1.1

# Test internet connectivity through router
ping 8.8.8.8
curl -I https://google.com
```

**Step 2: Verify Traffic Mirroring**

On OpenWrt:
```bash
# Check iptables TEE rules
iptables -t mangle -L -v -n | grep TEE

# Monitor mirrored interface
tcpdump -i eth0.3 -c 20
```

On WSL2:
```bash
# Capture packets on monitoring interface
sudo tcpdump -i eth0 -c 20 -n

# Should see traffic from your network
```

**Step 3: Verify Suricata is Receiving Traffic**

```bash
# Check Suricata packet stats
sudo suricatasc -c "pcap-current"

# Output should show:
# {
#   "message": {
#     "packets": 12345,
#     "drop": 0,
#     "invalid-checksums": 0
#   }
# }

# Real-time packet count
watch -n 1 'sudo suricatasc -c "pcap-current"'
```

---

## Alert Validation

### Generate Test Traffic

#### 1. EICAR Test File (Malware Detection)

```bash
# Download EICAR test file
curl http://testmyids.com/

# Alternative direct download
wget http://www.eicar.org/download/eicar.com
```

**Expected Alert:**
```
ET POLICY EICAR malware test file download detected
```

#### 2. Nmap Scan (Network Reconnaissance)

```bash
# From client device, scan router
nmap -sS -p 1-1000 192.168.1.1

# Aggressive scan
nmap -A -T4 192.168.1.1
```

**Expected Alerts:**
```
ET SCAN Potential SSH Scan
ET SCAN NMAP -sS window 1024
GPL SCAN nmap TCP
```

#### 3. SQL Injection Attempt (Web Attack)

```bash
# Test against vulnerable test site
curl "http://testphp.vulnweb.com/artists.php?artist=1' OR '1'='1"
```

**Expected Alert:**
```
ET WEB_SERVER SQL Injection Attempt
```

#### 4. Directory Traversal

```bash
# Attempt directory traversal
curl "http://example.com/../../../../etc/passwd"
```

**Expected Alert:**
```
ET WEB_SERVER Possible directory traversal attempt
```

### Verify Alerts Were Generated

```bash
# Check fast.log
sudo tail -n 50 /var/log/suricata/fast.log

# Search for specific alert
sudo grep "EICAR" /var/log/suricata/fast.log

# JSON formatted alerts
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert") | {timestamp: .timestamp, alert: .alert.signature, src_ip: .src_ip, dest_ip: .dest_ip}'
```

### Alert Analysis Examples

**View Top 10 Alerts:**
```bash
cat /var/log/suricata/eve.json |   jq -r 'select(.event_type=="alert") | .alert.signature' |   sort | uniq -c | sort -rn | head -10
```

**Alerts by Source IP:**
```bash
cat /var/log/suricata/eve.json |   jq -r 'select(.event_type=="alert") | .src_ip' |   sort | uniq -c | sort -rn
```

**Alerts by Severity:**
```bash
cat /var/log/suricata/eve.json |   jq 'select(.event_type=="alert") | {severity: .alert.severity, signature: .alert.signature}' |   jq -s 'group_by(.severity) | map({severity: .[0].severity, count: length})'
```

---

## Performance Testing

### Baseline Performance Metrics

#### 1. Packet Processing Rate

```bash
# Start Suricata with stats output
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 --init-errors-fatal -v

# Monitor performance
sudo suricatasc -c "dump-counters" | grep -E "capture.kernel_packets|capture.kernel_drops"
```

**Target Metrics:**
- Packet drop rate: <1%
- Processing latency: <100ms
- Memory usage: <500MB
- CPU usage: <25% (idle network)

#### 2. Throughput Testing with iPerf3

**On OpenWrt:**
```bash
opkg install iperf3
iperf3 -s
```

**On Client:**
```bash
# Test bandwidth without IDS
iperf3 -c 192.168.1.1 -t 30

# Monitor Suricata during test
sudo suricatasc -c "pcap-current"
```

**Expected Results:**
- Minimal impact on throughput (<5% reduction)
- No packet drops
- Consistent latency

#### 3. Load Testing

```bash
# Generate high traffic volume
for i in {1..100}; do
  curl -s http://example.com > /dev/null &
done

# Monitor Suricata performance
htop -u suricata
sudo iotop -u suricata
```

### Optimize Performance Issues

**If CPU usage is high:**

Edit `/etc/suricata/suricata.yaml`:
```yaml
# Reduce worker threads
threading:
  detect-thread-ratio: 1.0

# Disable unused features
app-layer:
  protocols:
    smb:
      enabled: no
    dcerpc:
      enabled: no
```

**If memory usage is high:**
```yaml
stream:
  memcap: 64mb
  reassembly:
    memcap: 128mb
```

---

## False Positive Reduction

### Identify False Positives

```bash
# Find most frequent alerts
cat /var/log/suricata/eve.json |   jq -r 'select(.event_type=="alert") | "\(.alert.signature) - \(.dest_ip)"' |   sort | uniq -c | sort -rn | head -20

# Investigate specific alert
cat /var/log/suricata/eve.json |   jq 'select(.event_type=="alert" and .alert.signature=="ALERT_NAME")'
```

### Common False Positives and Solutions

#### 1. Internal Network Scanning (Legitimate)

**Alert:** `ET SCAN Potential SSH Scan`

**Solution - Whitelist Internal IPs:**

Edit `/etc/suricata/threshold.config`:
```bash
# Suppress for internal management host
suppress gen_id 1, sig_id 2001219, track by_src, ip 192.168.1.100
```

#### 2. Routine Windows Updates

**Alert:** `ET POLICY Windows Update Check`

**Solution:**
```bash
# Disable Windows update policies
suppress gen_id 1, sig_id 2012647
```

#### 3. DNS Over HTTPS (DoH)

**Alert:** `ET POLICY DNS over HTTPS`

**Solution:**
```yaml
# In suricata.yaml, under modify rules
modify:
  - action: disable
    rules:
      - sid: 2029537
```

### Create Custom Suppressions

Create `/etc/suricata/suppress.conf`:

```bash
# Suppress specific rule for specific host
suppress gen_id 1, sig_id 2001219, track by_src, ip 192.168.1.50

# Suppress entire category
suppress gen_id 1, sig_id 2012647, track by_both

# Suppress for network range
suppress gen_id 1, sig_id 2010935, track by_src, ip 192.168.1.0/24
```

Include in `suricata.yaml`:
```yaml
suppress-gen:
  - file: /etc/suricata/suppress.conf
```

---

## SIEM Integration Testing

### Splunk Integration

#### 1. Configure Splunk Forwarder

```bash
# Install Splunk Universal Forwarder on WSL2
wget -O splunkforwarder.tgz 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?...'
sudo tar xvzf splunkforwarder.tgz -C /opt

# Configure inputs
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/suricata/eve.json   -sourcetype suricata:json   -index security

# Add forward server
sudo /opt/splunkforwarder/bin/splunk add forward-server splunk.example.com:9997
```

#### 2. Test Log Forwarding

```bash
# Generate test alert
curl http://testmyids.com

# Check forwarder queue
/opt/splunkforwarder/bin/splunk list forward-server

# Verify in Splunk
# Search: index=security sourcetype=suricata:json
```

### ELK Stack Integration

#### 1. Filebeat Configuration

Create `/etc/filebeat/filebeat.yml`:

```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/suricata/eve.json
  json.keys_under_root: true
  json.add_error_key: true
  fields:
    type: suricata

output.elasticsearch:
  hosts: ["elasticsearch.example.com:9200"]
  index: "suricata-%{+yyyy.MM.dd}"
```

#### 2. Test Connection

```bash
# Test Elasticsearch connection
filebeat test output

# Test configuration
filebeat test config

# Start Filebeat
sudo systemctl start filebeat
```

---

## Incident Response Testing

### Scenario 1: Port Scan Detection

**Simulate:**
```bash
nmap -sS 192.168.1.0/24
```

**Detect:**
```bash
# Alert should trigger
grep "SCAN" /var/log/suricata/fast.log
```

**Respond:**
```bash
# Block scanning IP on OpenWrt
ssh root@192.168.1.1
iptables -I INPUT -s <SCANNING_IP> -j DROP
```

### Scenario 2: Malware Download

**Simulate:**
```bash
wget http://testmyids.com/
```

**Detect:**
```bash
# Check for malware alert
grep "EICAR" /var/log/suricata/eve.json | jq
```

**Respond:**
```bash
# Quarantine infected host
# Block traffic from host
iptables -I FORWARD -s <INFECTED_IP> -j DROP
```

### Scenario 3: Data Exfiltration

**Simulate:**
```bash
# Large file transfer
dd if=/dev/urandom of=large_file.bin bs=1M count=100
curl -X POST -F "file=@large_file.bin" http://example.com/upload
```

**Detect:**
```bash
# Check for exfiltration alerts
grep "Large Outbound Transfer" /var/log/suricata/fast.log
```

**Respond:**
```bash
# Rate limit outbound connections
iptables -A OUTPUT -p tcp -m limit --limit 10/s -j ACCEPT
```

---

## Automated Testing Scripts

### Daily Health Check Script

Create `/root/ids-healthcheck.sh`:

```bash
#!/bin/bash

LOG_FILE="/var/log/ids-healthcheck.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "=== IDS Health Check - $DATE ===" >> $LOG_FILE

# Check Suricata service
if systemctl is-active --quiet suricata; then
    echo "✓ Suricata service: RUNNING" >> $LOG_FILE
else
    echo "✗ Suricata service: STOPPED" >> $LOG_FILE
    systemctl start suricata
fi

# Check packet processing
PACKETS=$(sudo suricatasc -c "pcap-current" | jq -r '.message.packets')
echo "✓ Packets processed: $PACKETS" >> $LOG_FILE

# Check for packet drops
DROPS=$(sudo suricatasc -c "pcap-current" | jq -r '.message.drop')
if [ "$DROPS" -gt 100 ]; then
    echo "⚠ High packet drop rate: $DROPS" >> $LOG_FILE
fi

# Check log file size
LOG_SIZE=$(du -h /var/log/suricata/eve.json | cut -f1)
echo "✓ Log file size: $LOG_SIZE" >> $LOG_FILE

# Check rule update age
RULE_AGE=$(find /var/lib/suricata/rules -name "*.rules" -mtime +7 | wc -l)
if [ "$RULE_AGE" -gt 0 ]; then
    echo "⚠ Rules older than 7 days. Running update..." >> $LOG_FILE
    sudo suricata-update
fi

echo "" >> $LOG_FILE
```

Add to crontab:
```bash
crontab -e
# Add:
0 8 * * * /root/ids-healthcheck.sh
```

---

## Validation Checklist

- [ ] Traffic mirroring functional from OpenWrt to WSL2
- [ ] Suricata receiving and processing packets
- [ ] Test alerts generated successfully (EICAR, Nmap, SQL injection)
- [ ] Alert logs written to eve.json and fast.log
- [ ] Performance metrics within acceptable range (<1% packet drop)
- [ ] False positives identified and suppressed
- [ ] SIEM integration tested and functional
- [ ] Incident response procedures tested
- [ ] Automated monitoring scripts deployed
- [ ] Documentation updated with findings

---

## Additional Resources

- [Suricata Testing Documentation](https://suricata.readthedocs.io/en/latest/devguide/unittests.html)
- [PCAP Testing Files](https://wiki.wireshark.org/SampleCaptures)
- [IDS Testing Tools](https://github.com/robcowart/testmyids)
- [Splunk Add-on for Suricata](https://splunkbase.splunk.com/app/2760/)

---

*Last Updated: November 2025*
