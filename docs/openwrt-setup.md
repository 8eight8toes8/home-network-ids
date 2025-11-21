# OpenWrt Router Configuration Guide

## Table of Contents
1. [Initial Router Setup](#initial-router-setup)
2. [Network Interface Configuration](#network-interface-configuration)
3. [Firewall Rules Implementation](#firewall-rules-implementation)
4. [Port Mirroring/SPAN Configuration](#port-mirroring-span-configuration)
5. [DMZ and Network Segmentation](#dmz-and-network-segmentation)
6. [Security Hardening](#security-hardening)

---

## Initial Router Setup

### Prerequisites
- OpenWrt 23.05+ compatible router
- Ethernet cable for initial configuration
- SSH client (PuTTY, Terminal, or WSL)

### First Boot Configuration

1. **Connect to Router**
   ```bash
   # Default IP after fresh install
   ssh root@192.168.1.1
   # Default password is usually empty - press Enter
   ```

2. **Set Root Password**
   ```bash
   passwd
   # Enter new strong password twice
   ```

3. **Update Package Lists**
   ```bash
   opkg update
   opkg list-upgradable
   opkg upgrade
   ```

4. **Install Essential Packages**
   ```bash
   # Network tools
   opkg install tcpdump nmap iperf3

   # Traffic monitoring
   opkg install vnstat luci-app-vnstat

   # Advanced firewall features
   opkg install iptables-mod-tee iptables-mod-extra

   # Web interface improvements
   opkg install luci-app-statistics luci-app-firewall
   ```

---

## Network Interface Configuration

### LAN Configuration

Edit `/etc/config/network`:

```bash
config interface 'lan'
    option type 'bridge'
    option ifname 'eth0.1'
    option proto 'static'
    option ipaddr '192.168.1.1'
    option netmask '255.255.255.0'
    option ip6assign '60'
```

### WAN Configuration

```bash
config interface 'wan'
    option ifname 'eth0.2'
    option proto 'dhcp'

config interface 'wan6'
    option ifname 'eth0.2'
    option proto 'dhcpv6'
```

### IDS Monitoring Interface

Create dedicated interface for Suricata traffic mirroring:

```bash
config interface 'monitor'
    option ifname 'eth0.3'
    option proto 'static'
    option ipaddr '192.168.100.1'
    option netmask '255.255.255.0'
```

**Apply Changes:**
```bash
/etc/init.d/network restart
```

---

## Firewall Rules Implementation

### Basic Firewall Zones

Edit `/etc/config/firewall`:

```bash
# LAN Zone - Trusted
config zone
    option name 'lan'
    option input 'ACCEPT'
    option output 'ACCEPT'
    option forward 'ACCEPT'
    option network 'lan'

# WAN Zone - Untrusted
config zone
    option name 'wan'
    option input 'REJECT'
    option output 'ACCEPT'
    option forward 'REJECT'
    option masq '1'
    option mtu_fix '1'
    option network 'wan wan6'

# DMZ Zone - Restricted
config zone
    option name 'dmz'
    option input 'REJECT'
    option output 'ACCEPT'
    option forward 'REJECT'
    option network 'dmz'
```

### Forwarding Rules

```bash
# Allow LAN to WAN
config forwarding
    option src 'lan'
    option dest 'wan'

# Allow LAN to DMZ
config forwarding
    option src 'lan'
    option dest 'dmz'

# Block DMZ to LAN
config forwarding
    option src 'dmz'
    option dest 'lan'
    option enabled '0'
```

### Custom Firewall Rules

Create `/etc/firewall.user`:

```bash
#!/bin/sh

# Drop invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Rate limit SSH connections
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP

# Log dropped packets
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Block common attack patterns
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
```

Make executable:
```bash
chmod +x /etc/firewall.user
```

---

## Port Mirroring/SPAN Configuration

### Method 1: Using TEE Target (Recommended)

Add to `/etc/firewall.user`:

```bash
# Mirror all traffic to IDS interface
iptables -t mangle -A PREROUTING -j TEE --gateway 192.168.100.2
iptables -t mangle -A POSTROUTING -j TEE --gateway 192.168.100.2
```

### Method 2: Using tc (Traffic Control)

```bash
# Install tc package
opkg install tc

# Create mirroring rule
tc qdisc add dev br-lan ingress
tc filter add dev br-lan parent ffff: protocol all u32 match u8 0 0 action mirred egress mirror dev eth0.3
```

### Verify Traffic Mirroring

```bash
# On OpenWrt router
tcpdump -i eth0.3 -c 10

# Should see mirrored packets
```

---

## DMZ and Network Segmentation

### VLAN Configuration

Edit `/etc/config/network`:

```bash
# VLAN 10 - Main LAN
config switch_vlan
    option device 'switch0'
    option vlan '1'
    option ports '0 1 2 3 6t'
    option vid '10'

# VLAN 20 - DMZ
config switch_vlan
    option device 'switch0'
    option vlan '2'
    option ports '4 6t'
    option vid '20'

# VLAN 100 - IDS Monitoring
config switch_vlan
    option device 'switch0'
    option vlan '3'
    option ports '5 6t'
    option vid '100'
```

### DMZ Interface Configuration

```bash
config interface 'dmz'
    option type 'bridge'
    option ifname 'eth0.20'
    option proto 'static'
    option ipaddr '192.168.20.1'
    option netmask '255.255.255.0'
```

### DHCP for DMZ

Edit `/etc/config/dhcp`:

```bash
config dhcp 'dmz'
    option interface 'dmz'
    option start '100'
    option limit '50'
    option leasetime '12h'
    option dhcpv6 'server'
    option ra 'server'
```

---

## Security Hardening

### Disable Unused Services

```bash
# List running services
/etc/init.d/*

# Disable unnecessary services
/etc/init.d/uhttpd disable
/etc/init.d/dnsmasq stop  # If using external DNS
```

### SSH Hardening

Edit `/etc/config/dropbear`:

```bash
config dropbear
    option PasswordAuth 'off'  # Use keys only
    option RootPasswordAuth 'off'
    option Port '2222'  # Non-standard port
    option Interface 'lan'  # LAN only
```

### Enable Logging

```bash
# Install logging daemon
opkg install logd

# Configure in /etc/config/system
config system
    option log_size '64'
    option log_ip '192.168.1.100'  # Remote syslog server
    option log_proto 'udp'
    option log_port '514'
```

### Automated Backup

Create `/root/backup.sh`:

```bash
#!/bin/sh
# Backup OpenWrt configuration

BACKUP_DIR="/tmp/backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup configuration
sysupgrade -b "$BACKUP_DIR/openwrt-backup-$DATE.tar.gz"

# Copy to remote location (optional)
scp "$BACKUP_DIR/openwrt-backup-$DATE.tar.gz" user@192.168.1.100:/backups/

echo "Backup completed: openwrt-backup-$DATE.tar.gz"
```

Add to crontab:
```bash
crontab -e
# Add line:
0 2 * * 0 /root/backup.sh
```

---

## Testing and Validation

### Test Internet Connectivity

```bash
ping -c 4 8.8.8.8
nslookup google.com
```

### Test Firewall Rules

```bash
# From LAN device
nmap -sT 192.168.1.1

# Should see only allowed ports open
```

### Monitor Traffic

```bash
# Real-time bandwidth monitoring
vnstat -l -i br-lan

# Live traffic capture
tcpdump -i br-lan -n
```

---

## Troubleshooting

### Network Not Working After Changes

```bash
# Revert network config
cp /rom/etc/config/network /etc/config/network
/etc/init.d/network restart
```

### Can't Access LuCI Web Interface

```bash
# Restart web server
/etc/init.d/uhttpd restart

# Check if running
netstat -tulpn | grep uhttpd
```

### Firewall Blocking Legitimate Traffic

```bash
# Temporarily disable firewall
/etc/init.d/firewall stop

# Check logs
logread | grep firewall

# Re-enable
/etc/init.d/firewall start
```

---

## Additional Resources

- [OpenWrt Documentation](https://openwrt.org/docs/start)
- [OpenWrt Forum](https://forum.openwrt.org/)
- [Network Configuration Guide](https://openwrt.org/docs/guide-user/base-system/basic-networking)
- [Firewall Configuration](https://openwrt.org/docs/guide-user/firewall/start)

---

*Last Updated: November 2025*
