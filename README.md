# Raspberry Pi Captive Portal

Complete setup for creating a WiFi access point with captive portal on Raspberry Pi. The Pi receives internet via **Ethernet** and shares it through **WiFi** with a "Terms of Service" agreement page that users must accept before gaining internet access.

## Overview

This setup creates a **walled garden** WiFi access point where:
- Users connect to WiFi but have no internet initially
- Captive portal automatically appears on iOS, Android, and Windows
- Users must accept terms to gain internet access
- Portal notification dismisses automatically after acceptance
- Systemd service ensures everything persists after reboot

This is work in progress and will not be updated regularly; see it as me sharing my playground with you rather than it being a complete solution.

## 🔧 Hardware Requirements

- **Raspberry Pi** (any model: Zero W, 3, 4, 5, or Compute Module)
- **WiFi Adapter** (built-in or USB)
  - For models without built-in WiFi (Pi Zero, Pi 1/2): USB WiFi required
  - For models with built-in WiFi: Can use built-in or add USB adapter
  - Recommended USB chipsets: RTL8188, RT5370, MT7601U, Atheros AR9271
  - Example: TP-Link TL-WN722N, Edimax EW-7811Un, Panda Wireless PAU05
- **Internet Connection** (one of):
  - Built-in Ethernet port (Pi 3B+, 4, 5)
  - USB Ethernet adapter (Pi Zero, 1, 2, or any model)
  - Another WiFi adapter (if you have 2 WiFi adapters total)
- **MicroSD card** (8GB+ minimum, 16GB+ recommended)
- **Power supply** (appropriate for your Pi model)

## 📋 Prerequisites

1. **Raspberry Pi OS** (Bullseye or newer) installed
2. **Internet connection** via Ethernet port
3. **USB WiFi dongle** plugged in
4. **SSH access** enabled (or keyboard/monitor attached)

## ✨ Features

- ✅ **Auto-detects network interfaces** (WiFi and ethernet)
- ✅ **Walled garden** - internet blocked until terms accepted
- ✅ **Proper captive portal detection** for iOS, Android, Windows
- ✅ **Automatic portal notification dismissal** after acceptance
- ✅ **Systemd service** for boot persistence
- ✅ **HTTP redirect** to portal for initial connection
- ✅ **IP forwarding** enabled for internet access
- ✅ **Interface-specific iptables rules** for proper routing

## 🚀 Quick Start

### 1. Prepare Your Raspberry Pi

```bash
# Update system
sudo apt update
sudo apt upgrade -y

# Verify WiFi adapter(s) detected
iw dev
# You should see at least one wlan interface

# Check network interfaces
ip link show
# Look for eth0, enx*, or similar for ethernet

# Verify internet connection (if ethernet connected)
ping -c 4 google.com
```

### 2. Download and Install

```bash
# Download the setup files
cd ~
git clone https://github.com/queueeee/rpi-captive-portal raspberry-pi-captive-portal
cd raspberry-pi-captive-portal

# Make setup script executable
chmod +x setup.sh

# Run installation (requires root)
sudo ./setup.sh
```

The script will:
1. Update system packages
2. Detect network interfaces automatically
3. Install required packages (hostapd, dnsmasq, nginx, php-fpm)
4. Configure WiFi access point
5. Set up walled garden firewall
6. Create systemd service for persistence
7. Configure captive portal detection
8. Start all services

**Note**: The script will auto-detect your network interfaces during installation and prompt you to confirm the configuration.

### 3. Reboot and Test

```bash
sudo reboot
```

After reboot:
1. **Connect** to the WiFi network "RaspberryPi-Portal" (password: wifi2025)
2. **You should see a captive portal notification** appear automatically
3. **Click to open the portal** and accept the terms
4. **The notification should dismiss automatically**
5. **You now have internet access**

## 📁 Project Structure

```
raspberry-pi-captive-portal/
├── setup.sh              # Main installation script
├── portal/
│   ├── index.html        # Terms of Service page
│   ├── accept.php        # Agreement handler
│   └── success.html      # Confirmation page
└── README.md            # This file
```

## ⚙️ Configuration

### Change WiFi Settings

Edit `setup.sh` before running:

```bash
AP_SSID="RaspberryPi-Portal"     # Network name
AP_PASSPHRASE="wifi2025"          # WiFi password (min 8 chars) - CHANGE THIS!
AP_CHANNEL=7                      # WiFi channel (1-13)
AP_IP="10.0.0.1"                  # Gateway IP
DHCP_START="10.0.0.10"            # DHCP range start
DHCP_END="10.0.0.50"              # DHCP range end
```

**Important**: Change the default WiFi password before deploying! Users will need to enter this password when connecting to the WiFi network.

### Change WiFi Password After Installation

If you've already installed and want to change the password:

```bash
# Edit the hostapd configuration
sudo nano /etc/hostapd/hostapd.conf

# Find and change this line:
# wpa_passphrase=wifi2025

# Save and exit (Ctrl+X, Y, Enter)

# Restart hostapd
sudo systemctl restart hostapd
```

Users will need to reconnect with the new password.

### Customize Terms Page

Edit `portal/index.html` to modify:
- Company name
- Terms and conditions text
- Styling and branding
- Logo/images

### View Accepted Clients

```bash
# View log of accepted users
sudo tail -f /var/log/captive-portal.log

# List connected clients
sudo list-portal-clients.sh
```

## 🔧 How It Works

### Walled Garden Architecture
- Default iptables policy: `FORWARD DROP` (blocks all internet)
- DNS queries allowed (port 53) for domain resolution
- HTTP/HTTPS to portal allowed for terms acceptance
- Everything else blocked until user accepts terms

### Terms Acceptance Flow
1. User connects to WiFi → receives IP from DHCP (10.0.0.10-50)
2. HTTP traffic redirected to portal via iptables NAT
3. Device checks detection URLs → sees captive portal
4. User accepts terms → `accept.php` is called
5. `accept.php` calls `grant-internet-access.sh` via sudo
6. Grant script adds interface-specific iptables rules:
   - `FORWARD -i wlan0 -o eth0 -s CLIENT_IP -j ACCEPT` (outbound)
   - `FORWARD -i eth0 -o wlan0 -d CLIENT_IP -j ACCEPT` (inbound)
   - NAT PREROUTING exemption for HTTP redirect
7. Device rechecks detection URLs → gets success code (204/200)
8. Portal notification automatically dismisses

### Captive Portal Detection
The system properly handles detection URLs for all major platforms:
- **iOS/macOS**: `/hotspot-detect.html`, `/library/test/success.html` → 200 OK
- **Android**: `/generate_204`, `/gen_204` → 204 No Content
- **Windows**: `/ncsi.txt`, `/connecttest.txt` → 200 OK with specific text

Detection URLs route to `check-portal.php` which:
- Checks if client IP has iptables FORWARD rule via `check-internet-access.sh`
- If accepted: returns appropriate success code to dismiss notification
- If not accepted: redirects to portal page

### Boot Persistence
The `captive-portal.service` systemd unit ensures everything persists after reboot:
- Enables IP forwarding (`net.ipv4.ip_forward=1`)
- Unblocks WiFi (RF-kill management)
- Configures WiFi interface with static IP
- Restores HTTP redirect rules
- Runs before hostapd/dnsmasq services

## 🛠️ Utility Scripts

After installation, these diagnostic commands are available:

### test-captive-portal.sh
Comprehensive diagnostic tool
```bash
sudo test-captive-portal.sh
```
Shows:
- Service status (hostapd, dnsmasq, nginx, php-fpm)
- WiFi interface status and IP configuration
- Firewall rules and policies
- Accepted clients count
- Recent portal logs

### list-portal-clients.sh
View connected clients and their status
```bash
sudo list-portal-clients.sh
```
Shows:
- DHCP leases (MAC, IP, hostname)
- Accepted clients with internet access
- Active iptables FORWARD rules

### grant-internet-access.sh
Manually grant internet access to an IP
```bash
sudo grant-internet-access.sh 10.0.0.25
```

### enable-portal-debug.sh
Enable detailed logging for troubleshooting
```bash
sudo enable-portal-debug.sh
```
Enables:
- Nginx debug logging
- PHP error logging
- Shows log file locations

## 🔍 Troubleshooting

### WiFi Adapter Not Detected

```bash
# Check if WiFi hardware is recognized
lsusb  # For USB adapters
dmesg | grep -i wireless

# Check wireless interfaces
iw dev
ip link show | grep wlan

# If driver is missing, install firmware packages
sudo apt install firmware-atheros firmware-realtek firmware-ralink firmware-brcm80211

# For specific chipsets
sudo apt install raspberrypi-kernel-headers
```

### Access Point Not Starting

```bash
# Check hostapd status
sudo systemctl status hostapd

# View logs
sudo journalctl -u hostapd -n 50

# Check captive portal service
sudo systemctl status captive-portal.service

# Check if RF-kill is blocking WiFi
sudo rfkill list

# Manually unblock
sudo rfkill unblock wifi

# Test hostapd configuration
sudo hostapd -dd /etc/hostapd/hostapd.conf
```

### Portal Doesn't Show

```bash
# Check all services
sudo systemctl status hostapd dnsmasq nginx

# Check if AP is broadcasting
iw dev wlan0 info

# Check HTTP redirect rule
sudo iptables -t nat -L PREROUTING -n -v

# Should see: DNAT tcp dpt:80 to:10.0.0.1:80

# Test portal manually
curl -i http://10.0.0.1/
```

### No Internet After Acceptance

```bash
# Check IP forwarding (CRITICAL!)
cat /proc/sys/net/ipv4/ip_forward
# MUST return: 1

# If it returns 0, enable it:
sudo sysctl -w net.ipv4.ip_forward=1
sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf

# Check FORWARD rules for your client IP
sudo iptables -L FORWARD -n -v | grep YOUR_IP

# Check NAT masquerading
sudo iptables -t nat -L POSTROUTING -n -v

# View acceptance logs
sudo journalctl -t captive-portal
sudo tail -f /var/log/captive-portal.log

# Check which interface has internet
ip link show
ping -c 2 8.8.8.8

# Restart services
sudo systemctl restart captive-portal.service
sudo systemctl restart hostapd dnsmasq
```

### Portal Notification Won't Dismiss

```bash
# Check detection URL response from client device
# Connect from phone/laptop and try:
curl -i http://10.0.0.1/generate_204

# Should return:
# - 204 No Content (if accepted)
# - 302 Found → redirect (if not accepted)

# Check if your IP has iptables rules
sudo iptables -L FORWARD -n | grep YOUR_CLIENT_IP

# Manually test acceptance
sudo grant-internet-access.sh YOUR_CLIENT_IP

# Check PHP execution
sudo tail -f /var/log/nginx/error.log
```

### WiFi Not Broadcasting After Reboot

```bash
# Check captive portal service (runs on boot)
sudo systemctl status captive-portal.service

# Check if interface has correct IP
ip addr show wlan0

# Should show: 10.0.0.1/24

# Check RF-kill status
sudo rfkill list

# Manually restart everything
sudo systemctl restart captive-portal.service
sleep 3
sudo systemctl restart hostapd
sudo systemctl restart dnsmasq
```

### Portal Page Not Loading

```bash
# Check nginx status
sudo systemctl status nginx

# View nginx logs
sudo tail -f /var/log/nginx/error.log

# Detect PHP version
php -v

# Check PHP-FPM
PHP_VER=$(php -r "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;")
sudo systemctl status php${PHP_VER}-fpm

# Check portal files exist
ls -la /var/www/portal/

# Check permissions
sudo chown -R www-data:www-data /var/www/portal
```

### DNS Not Working

```bash
# Check dnsmasq
sudo systemctl status dnsmasq

# View DNS queries
sudo tail -f /var/log/syslog | grep dnsmasq

# Test DNS resolution from client
nslookup google.com 10.0.0.1

# Restart dnsmasq
sudo systemctl restart dnsmasq
```

## 🔄 Recovery

If the portal causes boot issues, use the recovery script:
```bash
sudo /home/pi/recover-network.sh
```

This will:
- Stop and disable captive portal services
- Restore original network configuration (from backup)
- Reset WiFi interface to normal operation

## 📂 Files Created by Setup

### System Configuration
- `/etc/hostapd/hostapd.conf` - Access point configuration
- `/etc/dnsmasq.conf` - DHCP and DNS configuration
- `/etc/nginx/sites-available/captive-portal` - Web server config
- `/etc/systemd/system/captive-portal.service` - Boot service
- `/etc/sudoers.d/captive-portal` - Sudo permissions for www-data

### Scripts
- `/usr/local/bin/captive-portal-setup.sh` - Boot initialization
- `/usr/local/bin/captive-portal-cleanup.sh` - Shutdown cleanup
- `/usr/local/bin/grant-internet-access.sh` - Grant client access
- `/usr/local/bin/check-internet-access.sh` - Check client status
- `/usr/local/bin/test-captive-portal.sh` - Diagnostics
- `/usr/local/bin/list-portal-clients.sh` - List clients
- `/usr/local/bin/enable-portal-debug.sh` - Enable debugging

### Portal Files
- `/var/www/portal/index.html` - Terms of service page
- `/var/www/portal/accept.php` - Acceptance handler
- `/var/www/portal/check-portal.php` - Detection URL handler
- `/var/www/portal/portal-dismissed.html` - Success page
- `/var/www/portal/success.html` - Alternative success page

### Logs
- `/var/log/captive-portal.log` - Acceptance events
- `/var/log/nginx/access.log` - Web requests
- `/var/log/nginx/error.log` - Web errors

## 🛠️ Advanced Configuration

### Supported Hardware Combinations

The script automatically detects and supports:

| Pi Model | Internet Source | Access Point | Notes |
|----------|----------------|--------------|-------|
| Pi 4/5 | Built-in Ethernet | USB WiFi | Recommended setup |
| Pi 4/5 | Built-in Ethernet | Built-in WiFi | Works, but USB WiFi preferred |
| Pi 3B+ | Built-in Ethernet | Built-in WiFi | Built-in WiFi may be limited |
| Pi Zero W | USB Ethernet | Built-in WiFi | Requires USB hub + ethernet adapter |
| Pi Zero 2W | USB Ethernet | Built-in WiFi | Requires USB OTG adapter |
| Any Pi | 2x USB WiFi | One WiFi adapter | Script will let you choose which |
| Any Pi | None (standalone) | Any WiFi | Portal only, no internet |

### Use WiFi for Internet (Bridge Setup)

If you want to receive internet via WiFi and share via another WiFi:

1. Edit `/etc/wpa_supplicant/wpa_supplicant.conf`:
```bash
network={
    ssid="YourHomeWiFi"
    psk="YourPassword"
}
```

2. The script will detect both WiFi interfaces and let you choose which one for AP

### Add Time Limit to Access

Edit `portal/accept.php` to expire sessions after X hours:

```php
// Check if session expired (4 hours = 14400 seconds)
if (isset($_SESSION['accepted_time'])) {
    if (time() - $_SESSION['accepted_time'] > 14400) {
        session_destroy();
        header('Location: index.html');
        exit;
    }
}
```

### Bandwidth Limiting

```bash
# Install wondershaper
sudo apt install wondershaper

# Limit USB WiFi to 5Mbps down, 1Mbps up
sudo wondershaper wlan1 5000 1000
```

### Block Specific Websites

```bash
# Add to dnsmasq.conf
echo "address=/facebook.com/0.0.0.0" | sudo tee -a /etc/dnsmasq.conf
sudo systemctl restart dnsmasq
```

## 📊 Monitoring

### View Connected Clients

```bash
# List DHCP leases
cat /var/lib/misc/dnsmasq.leases

# List ARP table
arp -a

# View hostapd clients
sudo iw dev wlan1 station dump
```

### Monitor Traffic

```bash
# Install iftop
sudo apt install iftop

# Monitor WiFi interface
sudo iftop -i wlan1
```

## 🔒 Security Notes

- This is a **basic captive portal** - not enterprise-grade security
- WiFi network is **WPA2-protected** - users must enter password to connect
- **Default WiFi password is `wifi2025`** - CHANGE THIS before deployment!
- Traffic between clients and Pi uses WPA2 encryption
- Consider using **WPA2-Enterprise** for better security in production
- The portal **logs IP addresses and MAC addresses**
- The web server (www-data) has sudo permissions for **specific scripts only**
- Client IPs are **validated** before adding firewall rules
- iptables rules are **interface-specific** (not wildcards)
- HTTP redirect only applies to **unauthenticated clients**
- Keep system updated: `sudo apt update && sudo apt upgrade`

## 🔄 Uninstall

```bash
# Stop and disable services
sudo systemctl stop captive-portal.service hostapd dnsmasq nginx
sudo systemctl disable captive-portal.service hostapd dnsmasq

# Remove packages
sudo apt remove --purge hostapd dnsmasq nginx php-fpm

# Remove configuration files
sudo rm -rf /etc/hostapd/hostapd.conf
sudo rm -rf /etc/dnsmasq.conf
sudo rm -rf /etc/nginx/sites-available/captive-portal
sudo rm -rf /etc/systemd/system/captive-portal.service
sudo rm -rf /etc/sudoers.d/captive-portal

# Remove portal files
sudo rm -rf /var/www/portal

# Remove scripts
sudo rm -f /usr/local/bin/captive-portal-setup.sh
sudo rm -f /usr/local/bin/captive-portal-cleanup.sh
sudo rm -f /usr/local/bin/grant-internet-access.sh
sudo rm -f /usr/local/bin/check-internet-access.sh
sudo rm -f /usr/local/bin/test-captive-portal.sh
sudo rm -f /usr/local/bin/list-portal-clients.sh
sudo rm -f /usr/local/bin/enable-portal-debug.sh

# Restore iptables
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -P FORWARD ACCEPT
sudo netfilter-persistent save

# Restore network configuration
# If you have backups:
sudo cp /etc/dhcpcd.conf.backup /etc/dhcpcd.conf 2>/dev/null || true
sudo systemctl restart dhcpcd
```

## 📝 License

MIT License - Feel free to modify and distribute

## 🤝 Contributing

Issues and pull requests welcome!

## ℹ️ Support

For issues:
1. Check troubleshooting section above
2. Run diagnostics: `sudo test-captive-portal.sh`
3. Review system logs: `sudo journalctl -xe`
4. Check specific service: `sudo journalctl -u captive-portal -n 50`
5. Enable debug mode: `sudo enable-portal-debug.sh`

## 📚 Credits

Created for Raspberry Pi 4 running Raspberry Pi OS Bookworm.
Works with NetworkManager, dhcpcd, and systemd-networkd.

---

**Note**: This setup assumes Raspberry Pi OS (Bullseye or newer). Adjustments may be needed for other distributions.
