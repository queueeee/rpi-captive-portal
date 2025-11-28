#!/bin/bash
# Raspberry Pi 4 Captive Portal Setup Script
# This script sets up a WiFi access point with a captive portal

set -e

echo "======================================"
echo "Raspberry Pi Captive Portal Setup"
echo "======================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Configuration variables
AP_SSID="RaspberryPi-Portal"
AP_PASSPHRASE="wifi2025"  # Change this to your desired WiFi password
AP_CHANNEL=7
AP_IP="10.0.0.1"
AP_NETMASK="255.255.255.0"
DHCP_START="10.0.0.10"
DHCP_END="10.0.0.50"

# Network interfaces will be auto-detected
WIFI_INTERFACE=""
WAN_INTERFACE=""

echo "[1/8] Updating system packages..."
apt update
apt upgrade -y

echo "[2/9] Detecting network interfaces..."
echo "Scanning for available network interfaces..."

# Detect all ethernet interfaces (eth*, en*)
ETH_INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|en)' | grep -v '@')
if [ -z "$ETH_INTERFACES" ]; then
    echo "WARNING: No ethernet interface detected!"
    echo "Available interfaces:"
    ip link show
    read -p "Enter ethernet interface name manually (or press Enter to skip): " WAN_INTERFACE
else
    # Get the first ethernet interface that is up or can be brought up
    for iface in $ETH_INTERFACES; do
        # Check if interface exists and can be used
        if ip link show "$iface" &>/dev/null; then
            WAN_INTERFACE="$iface"
            echo "Found ethernet interface: $WAN_INTERFACE"
            break
        fi
    done
fi

# Detect all WiFi interfaces
WIFI_INTERFACES=$(iw dev | awk '$1=="Interface"{print $2}')
if [ -z "$WIFI_INTERFACES" ]; then
    echo "ERROR: No WiFi interfaces detected!"
    echo "Please ensure a WiFi adapter is connected."
    exit 1
fi

echo "Available WiFi interfaces:"
echo "$WIFI_INTERFACES" | nl

# Count WiFi interfaces
WIFI_COUNT=$(echo "$WIFI_INTERFACES" | wc -l)

if [ $WIFI_COUNT -eq 1 ]; then
    # Only one WiFi - use it for AP
    WIFI_INTERFACE=$(echo "$WIFI_INTERFACES" | head -n1)
    echo "Single WiFi interface detected: $WIFI_INTERFACE"
    echo "This will be used for the Access Point."
    if [ -z "$WAN_INTERFACE" ]; then
        echo "WARNING: No ethernet detected. Internet forwarding will not work!"
        read -p "Continue anyway? (y/N): " confirm
        if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
            exit 1
        fi
    fi
else
    # Multiple WiFi interfaces - let user choose or auto-select
    echo "Multiple WiFi interfaces detected."
    echo "Select which one to use for the Access Point:"
    echo "$WIFI_INTERFACES" | nl
    read -p "Enter number (or press Enter for auto-select): " wifi_choice
    
    if [ -z "$wifi_choice" ]; then
        # Auto-select: prefer USB WiFi (wlan1, wlan2, etc) over built-in (wlan0)
        WIFI_INTERFACE=$(echo "$WIFI_INTERFACES" | grep -v "wlan0" | head -n1)
        if [ -z "$WIFI_INTERFACE" ]; then
            WIFI_INTERFACE=$(echo "$WIFI_INTERFACES" | head -n1)
        fi
        echo "Auto-selected: $WIFI_INTERFACE"
    else
        WIFI_INTERFACE=$(echo "$WIFI_INTERFACES" | sed -n "${wifi_choice}p")
        if [ -z "$WIFI_INTERFACE" ]; then
            echo "ERROR: Invalid selection!"
            exit 1
        fi
        echo "Selected: $WIFI_INTERFACE"
    fi
fi

# Verify interfaces
if [ -z "$WIFI_INTERFACE" ]; then
    echo "ERROR: WiFi interface not set!"
    exit 1
fi

echo ""
echo "Configuration:"
echo "  Access Point Interface: $WIFI_INTERFACE"
if [ -n "$WAN_INTERFACE" ]; then
    echo "  Internet Interface: $WAN_INTERFACE"
else
    echo "  Internet Interface: NONE (no forwarding)"
fi
echo ""
read -p "Proceed with this configuration? (y/N): " proceed
if [ "$proceed" != "y" ] && [ "$proceed" != "Y" ]; then
    echo "Installation cancelled."
    exit 0
fi

echo "[3/8] Installing required packages..."
# Unblock WiFi first (some systems have it blocked by default)
rfkill unblock wifi 2>/dev/null || true

apt install -y hostapd dnsmasq iptables-persistent nginx php-fpm

echo "[4/8] Stopping services..."
systemctl unmask hostapd 2>/dev/null || true
systemctl stop hostapd 2>/dev/null || true
systemctl stop dnsmasq 2>/dev/null || true
systemctl stop nginx 2>/dev/null || true

echo "[5/8] Configuring hostapd (Access Point)..."
cat > /etc/hostapd/hostapd.conf << EOF
interface=$WIFI_INTERFACE
driver=nl80211
ssid=$AP_SSID
hw_mode=g
channel=$AP_CHANNEL
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=$AP_PASSPHRASE
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOF

# Configure hostapd to use this config
sed -i 's|^#DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd

echo "[6/8] Configuring network interfaces..."

# Detect which network manager is in use
NETWORK_MANAGER="none"
if systemctl is-active --quiet NetworkManager; then
    NETWORK_MANAGER="NetworkManager"
    echo "Detected: NetworkManager"
elif systemctl list-unit-files | grep -q "^dhcpcd.service"; then
    NETWORK_MANAGER="dhcpcd"
    echo "Detected: dhcpcd"
elif systemctl is-enabled --quiet systemd-networkd 2>/dev/null; then
    NETWORK_MANAGER="systemd-networkd"
    echo "Detected: systemd-networkd"
else
    echo "No network manager detected, will configure manually"
fi

# Configure based on detected network manager
if [ "$NETWORK_MANAGER" = "NetworkManager" ]; then
    echo "Configuring NetworkManager..."
    # Create connection profile for static IP
    cat > /etc/NetworkManager/system-connections/${WIFI_INTERFACE}-ap.nmconnection << EOF
[connection]
id=${WIFI_INTERFACE}-ap
type=wifi
interface-name=${WIFI_INTERFACE}

[wifi]
mode=ap
ssid=${AP_SSID}

[ipv4]
method=manual
address1=${AP_IP}/24

[ipv6]
method=disabled
EOF
    chmod 600 /etc/NetworkManager/system-connections/${WIFI_INTERFACE}-ap.nmconnection
    # Tell NetworkManager to ignore this interface for hostapd to manage it
    cat > /etc/NetworkManager/conf.d/unmanaged-${WIFI_INTERFACE}.conf << EOF
[keyfile]
unmanaged-devices=interface-name:${WIFI_INTERFACE}
EOF
    systemctl reload NetworkManager
    
elif [ "$NETWORK_MANAGER" = "dhcpcd" ]; then
    echo "Configuring dhcpcd..."
    # Backup dhcpcd.conf before modifying
    if [ -f /etc/dhcpcd.conf ] && [ ! -f /etc/dhcpcd.conf.backup ]; then
        cp /etc/dhcpcd.conf /etc/dhcpcd.conf.backup
        echo "Backed up dhcpcd.conf to /etc/dhcpcd.conf.backup"
    fi
    
    # Configure dhcpcd to ignore the WiFi interface
    if [ -f /etc/dhcpcd.conf ]; then
        # Remove any existing denyinterfaces lines for this interface
        sed -i "/denyinterfaces $WIFI_INTERFACE/d" /etc/dhcpcd.conf
        # Remove any existing static config for this interface
        sed -i "/interface $WIFI_INTERFACE/,/^$/d" /etc/dhcpcd.conf
    fi
    
    # Configure static IP for WiFi interface using dhcpcd
    if [ -f /etc/dhcpcd.conf ]; then
        cat >> /etc/dhcpcd.conf << EOF

# Static IP for captive portal access point
interface $WIFI_INTERFACE
    static ip_address=$AP_IP/24
    nohook wpa_supplicant
EOF
    fi
    
elif [ "$NETWORK_MANAGER" = "systemd-networkd" ]; then
    echo "Configuring systemd-networkd..."
    cat > /etc/systemd/network/10-${WIFI_INTERFACE}-ap.network << EOF
[Match]
Name=${WIFI_INTERFACE}

[Network]
Address=${AP_IP}/24
DHCP=no
IPForward=yes
EOF
    systemctl enable systemd-networkd
fi

echo "[7/8] Configuring dnsmasq (DHCP + DNS)..."
mv /etc/dnsmasq.conf /etc/dnsmasq.conf.bak 2>/dev/null || true
cat > /etc/dnsmasq.conf << EOF
# Interface configuration
interface=$WIFI_INTERFACE
dhcp-range=$DHCP_START,$DHCP_END,255.255.255.0,24h

# Forward DNS to real servers
server=8.8.8.8
server=8.8.4.4

# Hijack captive portal detection domains only
address=/captive.apple.com/$AP_IP
address=/connectivitycheck.gstatic.com/$AP_IP
address=/clients3.google.com/$AP_IP
address=/www.msftconnecttest.com/$AP_IP

# DHCP options
dhcp-option=3,$AP_IP
dhcp-option=6,$AP_IP

# Log queries
log-queries
log-dhcp

# Never forward addresses in private ranges
bogus-priv

# Listen on specific interface only
bind-interfaces
EOF

echo "[8/9] Configuring IP forwarding and iptables (Walled Garden)..."
# Enable IP forwarding
if [ -f /etc/sysctl.conf ]; then
    sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
else
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.conf
fi
echo 1 > /proc/sys/net/ipv4/ip_forward

# Flush existing rules
iptables -t nat -F
iptables -F

# Configure NAT (forward from WiFi AP to internet)
if [ -n "$WAN_INTERFACE" ]; then
    echo "Configuring NAT for internet forwarding..."
    iptables -t nat -A POSTROUTING -o $WAN_INTERFACE -j MASQUERADE
else
    echo "WARNING: No internet interface configured - clients won't have internet access"
fi

# Allow DNS and HTTP/HTTPS to the Pi itself (for portal access)
iptables -A INPUT -i $WIFI_INTERFACE -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -i $WIFI_INTERFACE -p udp --dport 53 -j ACCEPT
iptables -A INPUT -i $WIFI_INTERFACE -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -i $WIFI_INTERFACE -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -i $WIFI_INTERFACE -p udp --dport 67:68 -j ACCEPT

# WALLED GARDEN: Block all forwarding by default
echo "Enabling walled garden mode - users must accept terms to get internet..."
iptables -P FORWARD DROP

# Allow DNS queries through
iptables -A FORWARD -i $WIFI_INTERFACE -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -i $WIFI_INTERFACE -p tcp --dport 53 -j ACCEPT

# Allow HTTP/HTTPS to captive portal IP only
iptables -A FORWARD -i $WIFI_INTERFACE -d $AP_IP -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -i $WIFI_INTERFACE -d $AP_IP -p tcp --dport 443 -j ACCEPT

# Allow established connections back from internet
if [ -n "$WAN_INTERFACE" ]; then
    iptables -A FORWARD -i $WAN_INTERFACE -o $WIFI_INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
fi

# Note: Individual clients will be granted access via accept.php calling grant-internet-access.sh
# which adds interface-specific FORWARD rules and HTTP redirect exemption

# Add HTTP redirect to captive portal for all HTTP traffic
echo "Configuring HTTP redirect to portal..."
iptables -t nat -I PREROUTING 1 -i $WIFI_INTERFACE -p tcp --dport 80 -j DNAT --to-destination $AP_IP:80

# Save iptables rules
netfilter-persistent save

echo "✓ Walled garden enabled - clients blocked until terms accepted"
echo "✓ HTTP redirect configured - all HTTP traffic goes to portal"

echo "[9/9] Configuring nginx web server and portal files..."
# Copy portal files from script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
mkdir -p /var/www/portal
if [ -d "$SCRIPT_DIR/portal" ]; then
    cp "$SCRIPT_DIR/portal"/* /var/www/portal/
    echo "Portal files copied successfully"
else
    echo "ERROR: Portal files not found at $SCRIPT_DIR/portal"
    echo "Please ensure portal/ directory exists in the same location as setup.sh"
fi

# Detect PHP version
PHP_VERSION=$(php -r "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;" 2>/dev/null || echo "8.2")
echo "Detected PHP version: $PHP_VERSION"

# Configure nginx with proper captive portal detection
cat > /etc/nginx/sites-available/captive-portal << EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    server_name _;
    
    root /var/www/portal;
    index index.html index.php;
    
    # Captive portal detection - use PHP to check acceptance status
    # iOS/macOS
    location = /hotspot-detect.html {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME /var/www/portal/check-portal.php;
        fastcgi_param REQUEST_URI \\\$request_uri;
        fastcgi_pass unix:/var/run/php/php${PHP_VERSION}-fpm.sock;
    }
    
    location = /library/test/success.html {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME /var/www/portal/check-portal.php;
        fastcgi_param REQUEST_URI \\\$request_uri;
        fastcgi_pass unix:/var/run/php/php${PHP_VERSION}-fpm.sock;
    }
    
    # Android
    location = /generate_204 {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME /var/www/portal/check-portal.php;
        fastcgi_param REQUEST_URI \\\$request_uri;
        fastcgi_pass unix:/var/run/php/php${PHP_VERSION}-fpm.sock;
    }
    
    location = /gen_204 {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME /var/www/portal/check-portal.php;
        fastcgi_param REQUEST_URI \\\$request_uri;
        fastcgi_pass unix:/var/run/php/php${PHP_VERSION}-fpm.sock;
    }
    
    # Windows
    location = /ncsi.txt {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME /var/www/portal/check-portal.php;
        fastcgi_param REQUEST_URI \\\$request_uri;
        fastcgi_pass unix:/var/run/php/php${PHP_VERSION}-fpm.sock;
    }
    
    location = /connecttest.txt {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME /var/www/portal/check-portal.php;
        fastcgi_param REQUEST_URI \\\$request_uri;
        fastcgi_pass unix:/var/run/php/php${PHP_VERSION}-fpm.sock;
    }
    
    # Portal pages
    location = /portal-dismissed.html {
        try_files \\\$uri =404;
    }
    
    location = /success.html {
        try_files \\\$uri =404;
    }
    
    # Main portal page
    location = /index.html {
    }
    
    # PHP files (exact match has priority over prefix match)
    location = /accept.php {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php${PHP_VERSION}-fpm.sock;
    }
    
    # PHP processing for other PHP files
    location ~ \\.php\\\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php${PHP_VERSION}-fpm.sock;
    }
    
    # Redirect all other requests to index.html
    location / {
        return 302 http://\\\$host/index.html;
    }
    
    location @redirect_portal {
        return 302 http://\\\$host/index.html;
    }
    
    # Deny access to hidden files
    location ~ /\\. {
        deny all;
    }
}
EOF

# Create check-portal.php to handle detection URLs
cat > /var/www/portal/check-portal.php << 'CHECKPHP_EOF'
<?php
// check-portal.php - Handle captive portal detection checks
// Check if client has internet access granted via iptables

$clientIP = $_SERVER['REMOTE_ADDR'];

// Check if client has iptables rule (has internet access)
exec("sudo /usr/local/bin/check-internet-access.sh " . escapeshellarg($clientIP), $output, $return_code);
$hasInternetAccess = ($return_code === 0);

// If user has internet access, return success codes to dismiss captive portal
if ($hasInternetAccess) {
    // Determine which detection endpoint was requested
    $requestUri = $_SERVER['REQUEST_URI'];
    
    if (strpos($requestUri, 'generate_204') !== false) {
        // Android - return 204 No Content
        http_response_code(204);
        exit;
    } elseif (strpos($requestUri, 'ncsi.txt') !== false) {
        // Windows NCSI
        http_response_code(200);
        header('Content-Type: text/plain');
        echo 'Microsoft NCSI';
        exit;
    } elseif (strpos($requestUri, 'connecttest.txt') !== false) {
        // Windows Connect Test
        http_response_code(200);
        header('Content-Type: text/plain');
        echo 'Microsoft Connect Test';
        exit;
    } else {
        // iOS/macOS - return 200 with Success HTML
        http_response_code(200);
        header('Content-Type: text/html');
        echo '<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>';
        exit;
    }
}

// User hasn't accepted yet - redirect to portal
header('Location: http://' . $_SERVER['HTTP_HOST'] . '/index.html');
exit;
?>
CHECKPHP_EOF

# Enable site
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/captive-portal /etc/nginx/sites-enabled/

# Set permissions
chown -R www-data:www-data /var/www/portal
chmod -R 755 /var/www/portal

# Create log file with correct permissions
touch /var/log/captive-portal.log
chown www-data:www-data /var/log/captive-portal.log
chmod 664 /var/log/captive-portal.log

# Create grant-internet-access.sh script with interface-specific rules
echo "Installing internet access grant script..."
cat > /usr/local/bin/grant-internet-access.sh << 'GRANT_EOF'
#!/bin/bash
# Grant internet access to a specific client IP
CLIENT_IP="$1"

if [ -z "$CLIENT_IP" ]; then
    exit 1
fi

# Validate IP format
if ! [[ "$CLIENT_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    exit 1
fi

# Get WiFi and WAN interfaces
WIFI_IFACE=$(ls /sys/class/net/ | grep -E '^wlan' | head -n1)
WAN_IFACE=$(ls /sys/class/net/ | grep -E '^(eth|en)' | head -n1)

# Check if FORWARD rule already exists (for traffic FROM wifi TO wan)
if iptables -C FORWARD -i "$WIFI_IFACE" -o "$WAN_IFACE" -s "$CLIENT_IP" -j ACCEPT 2>/dev/null; then
    logger -t captive-portal "Client $CLIENT_IP already has internet access"
else
    # Add FORWARD rule to allow internet access (outbound)
    iptables -I FORWARD 1 -i "$WIFI_IFACE" -o "$WAN_IFACE" -s "$CLIENT_IP" -j ACCEPT
    # Add return traffic rule
    iptables -I FORWARD 1 -i "$WAN_IFACE" -o "$WIFI_IFACE" -d "$CLIENT_IP" -j ACCEPT
    logger -t captive-portal "Granted internet access to $CLIENT_IP"
fi

# Exempt this client from HTTP redirect so they can browse normally
if [ -n "$WIFI_IFACE" ]; then
    # Check if exempt rule exists
    if ! iptables -t nat -C PREROUTING -i "$WIFI_IFACE" -s "$CLIENT_IP" -p tcp --dport 80 -j ACCEPT 2>/dev/null; then
        # Add rule to exempt this IP from HTTP redirect (place before the redirect rule)
        iptables -t nat -I PREROUTING 1 -i "$WIFI_IFACE" -s "$CLIENT_IP" -p tcp --dport 80 -j ACCEPT
        logger -t captive-portal "Exempted $CLIENT_IP from HTTP redirect"
    fi
fi

exit 0
GRANT_EOF
chmod 755 /usr/local/bin/grant-internet-access.sh
echo "✓ Grant script created"

# Create check-internet-access.sh script
cat > /usr/local/bin/check-internet-access.sh << 'CHECKSCRIPT_EOF'
#!/bin/bash
# Check if a client IP has internet access (iptables rule exists)
CLIENT_IP="$1"

if [ -z "$CLIENT_IP" ]; then
    exit 1
fi

# Validate IP format
if ! [[ "$CLIENT_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    exit 1
fi

# Get WiFi and WAN interfaces
WIFI_IFACE=$(ls /sys/class/net/ | grep -E '^wlan' | head -n1)
WAN_IFACE=$(ls /sys/class/net/ | grep -E '^(eth|en)' | head -n1)

# Check if iptables rule exists for this IP (check the specific interface-based rule)
if iptables -C FORWARD -i "$WIFI_IFACE" -o "$WAN_IFACE" -s "$CLIENT_IP" -j ACCEPT 2>/dev/null; then
    exit 0
else
    exit 1
fi
CHECKSCRIPT_EOF
chmod 755 /usr/local/bin/check-internet-access.sh
echo "✓ Check script installed"

# Allow www-data to run both scripts without password
echo "Configuring sudo permissions for web server..."
cat > /etc/sudoers.d/captive-portal << 'SUDOERS_EOF'
www-data ALL=(ALL) NOPASSWD: /usr/local/bin/grant-internet-access.sh
www-data ALL=(ALL) NOPASSWD: /usr/local/bin/check-internet-access.sh
SUDOERS_EOF
chmod 440 /etc/sudoers.d/captive-portal
echo "✓ Sudoers configured"

echo ""
echo "======================================"
echo "Configuration Complete!"
echo "======================================"
echo ""
echo "Creating systemd service for boot persistence..."

# Create captive portal service
cat > /etc/systemd/system/captive-portal.service << 'SERVICE_EOF'
[Unit]
Description=Captive Portal HTTP Redirect Service
After=network.target
Before=hostapd.service dnsmasq.service
Wants=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/captive-portal-setup.sh
ExecStop=/usr/local/bin/captive-portal-cleanup.sh

[Install]
WantedBy=multi-user.target
SERVICE_EOF

# Create setup script that runs on boot
cat > /usr/local/bin/captive-portal-setup.sh << 'SETUP_EOF'
#!/bin/bash
# Setup iptables rules for captive portal

# Enable IP forwarding (critical for internet access!)
echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1

# Unblock WiFi (in case RF-kill is blocking it)
rfkill unblock wifi

# Wait for network interface to be ready
sleep 3

# Get WiFi interface
WIFI_IFACE=$(ls /sys/class/net/ | grep -E '^wlan' | head -n1)

if [ -z "$WIFI_IFACE" ]; then
    echo "ERROR: WiFi interface not found"
    logger -t captive-portal "ERROR: WiFi interface not found"
    exit 1
fi

# Configure WiFi interface with static IP
ip addr flush dev $WIFI_IFACE 2>/dev/null || true
ip addr add 10.0.0.1/24 dev $WIFI_IFACE
ip link set $WIFI_IFACE up

# Wait a moment for interface to be fully up
sleep 2

# Remove any existing HTTP redirect rules
iptables -t nat -D PREROUTING -i $WIFI_IFACE -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80 2>/dev/null || true

# Add HTTP redirect for all clients
iptables -t nat -I PREROUTING 1 -i $WIFI_IFACE -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80

logger -t captive-portal "HTTP redirect configured on $WIFI_IFACE"
exit 0
SETUP_EOF
chmod +x /usr/local/bin/captive-portal-setup.sh

# Create cleanup script that runs on shutdown
cat > /usr/local/bin/captive-portal-cleanup.sh << 'CLEANUP_EOF'
#!/bin/bash
# Cleanup iptables rules for captive portal

WIFI_IFACE=$(iw dev | awk '$1=="Interface"{print $2}' | head -n1)

if [ -n "$WIFI_IFACE" ]; then
    iptables -t nat -D PREROUTING -i $WIFI_IFACE -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80 2>/dev/null || true
    logger -t captive-portal "HTTP redirect removed from $WIFI_IFACE"
fi

exit 0
CLEANUP_EOF
chmod +x /usr/local/bin/captive-portal-cleanup.sh

# Enable the service
systemctl daemon-reload
systemctl enable captive-portal.service
echo "✓ Captive portal service created and enabled"

echo ""
echo "Creating utility scripts..."

# Create test-portal.sh diagnostic script
cat > /usr/local/bin/test-captive-portal.sh << 'TEST_EOF'
#!/bin/bash
# Test and diagnose captive portal
echo "=========================================="
echo "Captive Portal Diagnostics"
echo "=========================================="
echo ""

echo "=== Service Status ==="
systemctl is-active hostapd dnsmasq nginx | paste -d' ' <(echo -e "hostapd\ndnsmasq\nnginx") -
echo ""

PHP_VERSION=$(php -r "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;" 2>/dev/null || echo "8.2")
echo "=== PHP-FPM Status ==="
systemctl is-active php${PHP_VERSION}-fpm && echo "php${PHP_VERSION}-fpm: active" || echo "php${PHP_VERSION}-fpm: inactive"
echo ""

echo "=== WiFi Interface ==="
WIFI_IFACE=$(iw dev | awk '$1=="Interface"{print $2}' | head -n1)
if [ -n "$WIFI_IFACE" ]; then
    echo "Interface: $WIFI_IFACE"
    ip addr show $WIFI_IFACE | grep -E "inet |state"
    echo ""
    if iw dev $WIFI_IFACE info | grep -q "type AP"; then
        AP_SSID=$(iw dev $WIFI_IFACE info | grep ssid | awk '{print $2}')
        echo "✓ Broadcasting as AP: $AP_SSID"
    else
        echo "⚠ Not in AP mode"
    fi
else
    echo "⚠ No WiFi interface found"
fi
echo ""

echo "=== Firewall Rules (Walled Garden) ==="
echo "FORWARD policy: $(iptables -L FORWARD | head -1)"
ACCEPTED_COUNT=$(iptables -L FORWARD -n | grep -c "ACCEPT.*10.0.0" || echo "0")
echo "Accepted clients: $ACCEPTED_COUNT"
echo ""

echo "=== Recent Accepted Clients ==="
if [ -f /tmp/accepted_clients.txt ]; then
    tail -5 /tmp/accepted_clients.txt 2>/dev/null | sort -u || echo "None"
else
    echo "No accepted clients yet"
fi
echo ""

echo "=== Portal Logs (last 5) ==="
tail -5 /var/log/captive-portal.log 2>/dev/null || echo "No logs yet"
echo ""

echo "=== PHP Socket ==="
PHP_SOCK=$(ls /var/run/php/php*-fpm.sock 2>/dev/null | head -1)
if [ -n "$PHP_SOCK" ]; then
    echo "✓ PHP-FPM socket: $PHP_SOCK"
else
    echo "⚠ No PHP-FPM socket found"
fi
echo ""

echo "=== Portal Files ==="
ls -lh /var/www/portal/ 2>/dev/null || echo "Portal directory not found"
echo ""

echo "=========================================="
echo "Manual Tests:"
echo "  Test portal: curl -I http://10.0.0.1/"
echo "  Test PHP: curl -X POST http://10.0.0.1/accept.php -d 'agree=1'"
echo "  View logs: sudo tail -f /var/log/captive-portal.log"
echo "  Grant access: sudo grant-internet-access.sh 10.0.0.15"
echo "  View firewall: sudo iptables -L FORWARD -n -v"
echo "=========================================="
TEST_EOF
chmod 755 /usr/local/bin/test-captive-portal.sh
echo "✓ Created test-captive-portal.sh"

# Create list-connected-clients.sh
cat > /usr/local/bin/list-portal-clients.sh << 'LIST_EOF'
#!/bin/bash
# List all clients connected to the captive portal
echo "=========================================="
echo "Captive Portal - Connected Clients"
echo "=========================================="
echo ""

WIFI_IFACE=$(iw dev | awk '$1=="Interface"{print $2}' | head -n1)

echo "=== DHCP Leases ==="
if [ -f /var/lib/misc/dnsmasq.leases ]; then
    echo "Time                MAC Address       IP Address    Hostname"
    echo "----------------------------------------------------------------"
    cat /var/lib/misc/dnsmasq.leases | awk '{print $1, $2, $3, $4}'
else
    echo "No DHCP leases file found"
fi
echo ""

echo "=== Accepted Clients (Have Internet) ==="
if [ -f /tmp/accepted_clients.txt ]; then
    echo "IP Address    | Access Granted"
    echo "--------------------------------"
    sort -u /tmp/accepted_clients.txt | while read ip; do
        if iptables -C FORWARD -s "$ip" -j ACCEPT 2>/dev/null; then
            echo "$ip        ✓ Active"
        else
            echo "$ip        ✗ Expired"
        fi
    done
else
    echo "No accepted clients yet"
fi
echo ""

echo "=== Active Firewall Rules ==="
iptables -L FORWARD -n | grep "ACCEPT.*10.0.0" | awk '{print $4 " - ALLOWED"}' || echo "No client rules"
echo ""
echo "=========================================="
LIST_EOF
chmod 755 /usr/local/bin/list-portal-clients.sh
echo "✓ Created list-portal-clients.sh"

# Create enable-client-debug.sh
cat > /usr/local/bin/enable-portal-debug.sh << 'DEBUG_EOF'
#!/bin/bash
# Enable detailed logging for troubleshooting
echo "Enabling debug mode for captive portal..."

PHP_VERSION=$(php -r "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;" 2>/dev/null || echo "8.2")

# Enable nginx error logging
sed -i 's/error_log.*/error_log \/var\/log\/nginx\/error.log debug;/' /etc/nginx/nginx.conf 2>/dev/null || true

# Enable PHP error logging
cat >> /etc/php/${PHP_VERSION}/fpm/php.ini << EOF
display_errors = On
error_reporting = E_ALL
log_errors = On
error_log = /var/log/php${PHP_VERSION}-fpm-errors.log
EOF

systemctl restart nginx
systemctl restart php${PHP_VERSION}-fpm

echo "✓ Debug mode enabled"
echo ""
echo "View logs with:"
echo "  sudo tail -f /var/log/nginx/error.log"
echo "  sudo tail -f /var/log/php${PHP_VERSION}-fpm-errors.log"
echo "  sudo tail -f /var/log/captive-portal.log"
DEBUG_EOF
chmod 755 /usr/local/bin/enable-portal-debug.sh
echo "✓ Created enable-portal-debug.sh"

echo ""
echo "======================================"
echo "Setup Complete!"
echo "======================================"
echo ""
echo "Network Configuration:"
if [ -n "$WAN_INTERFACE" ]; then
    echo "  Internet Source: $WAN_INTERFACE"
else
    echo "  Internet Source: NONE (standalone AP only)"
fi
echo "  WiFi Access Point: $WIFI_INTERFACE"
echo "  SSID: $AP_SSID"
echo "  Password: $AP_PASSPHRASE"
echo "  Gateway IP: $AP_IP"
echo "  DHCP Range: $DHCP_START - $DHCP_END"
echo "  Mode: Walled Garden (internet blocked until acceptance)"
echo ""
echo "Installed Utility Commands:"
echo "  test-captive-portal.sh      - Diagnose portal issues"
echo "  list-portal-clients.sh      - View connected clients"
echo "  enable-portal-debug.sh      - Enable detailed logging"
echo "  grant-internet-access.sh    - Manually grant access to IP"
echo ""
echo "IMPORTANT: Creating recovery script in case of boot issues..."

# Create recovery script
cat > /home/pi/recover-network.sh << 'RECOVERY_EOF'
#!/bin/bash
# Recovery script to restore network if captive portal causes issues
echo "=========================================="
echo "Network Recovery Script"
echo "=========================================="
echo "This will disable the captive portal and restore normal network access."
echo ""
read -p "Continue? (y/N): " confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "Cancelled."
    exit 0
fi

echo ""
echo "Stopping services..."
systemctl stop hostapd
systemctl disable hostapd
systemctl stop dnsmasq
systemctl disable dnsmasq

echo "Restoring network configuration..."
# Restore dhcpcd
if [ -f /etc/dhcpcd.conf.backup ]; then
    cp /etc/dhcpcd.conf.backup /etc/dhcpcd.conf
    echo "✓ dhcpcd.conf restored"
else
    echo "⚠ No backup found, removing captive portal config manually..."
    # Remove the captive portal static IP config
    WIFI_IFACE=$(iw dev | awk '$1=="Interface"{print $2}' | head -n1)
    if [ -n "$WIFI_IFACE" ]; then
        sed -i "/# Static IP for captive portal/,/nohook wpa_supplicant/d" /etc/dhcpcd.conf
    fi
fi

echo "Restarting network services..."
systemctl restart dhcpcd
sleep 2

echo "Resetting WiFi interface..."
WIFI_IFACE=$(iw dev | awk '$1=="Interface"{print $2}' | head -n1)
if [ -n "$WIFI_IFACE" ]; then
    ip link set $WIFI_IFACE down
    sleep 1
    ip link set $WIFI_IFACE up
    echo "✓ WiFi interface reset: $WIFI_IFACE"
fi

echo ""
echo "=========================================="
echo "✓ Network Restored!"
echo "=========================================="
echo ""
echo "Your Pi should now have normal network access."
echo "To re-run captive portal setup:"
echo "  cd ~/raspberry-pi-captive-portal && sudo ./setup.sh"
echo ""
echo "Or to fix existing installation:"
echo "  cd ~/raspberry-pi-captive-portal && sudo ./fix-current-installation.sh"
RECOVERY_EOF

chmod +x /home/pi/recover-network.sh
chown pi:pi /home/pi/recover-network.sh

echo ""
echo "Recovery script created at: /home/pi/recover-network.sh"
echo "If your Pi won't boot after reboot, you can recover by:"
echo "  1. Connect via serial console or recovery mode"
echo "  2. Run: sudo /home/pi/recover-network.sh"
echo ""
echo "Next steps:"
echo "1. Review the configuration above"
echo "2. Reboot the Raspberry Pi: sudo reboot"
echo "3. Connect to the WiFi network '$AP_SSID'"
echo "4. You should be redirected to the agreement page"
echo ""
echo "Enabling and starting services..."

# Configure network interface BEFORE enabling services
echo "Configuring WiFi interface..."
ip link set $WIFI_INTERFACE down
sleep 1

# Restart appropriate network service
if [ "$NETWORK_MANAGER" = "dhcpcd" ]; then
    echo "Restarting dhcpcd..."
    systemctl restart dhcpcd
    sleep 3
elif [ "$NETWORK_MANAGER" = "NetworkManager" ]; then
    echo "Reloading NetworkManager..."
    systemctl reload NetworkManager
    sleep 2
elif [ "$NETWORK_MANAGER" = "systemd-networkd" ]; then
    echo "Restarting systemd-networkd..."
    systemctl restart systemd-networkd
    sleep 3
fi

# Manually configure interface if needed
echo "Setting up interface manually..."
ip addr flush dev $WIFI_INTERFACE 2>/dev/null || true
ip addr add ${AP_IP}/24 dev $WIFI_INTERFACE
ip link set $WIFI_INTERFACE up
sleep 2

# Verify interface has correct IP
if ip addr show $WIFI_INTERFACE | grep -q "$AP_IP"; then
    echo "✓ WiFi interface configured with IP $AP_IP"
else
    echo "⚠ WARNING: WiFi interface may not have correct IP address"
    echo "Current configuration:"
    ip addr show $WIFI_INTERFACE | grep inet || echo "No IP assigned"
fi

# Unmask and enable services
echo "Enabling services..."
systemctl unmask hostapd
systemctl enable hostapd
systemctl enable dnsmasq
systemctl enable nginx
systemctl enable php${PHP_VERSION}-fpm
systemctl enable captive-portal.service

# Start captive portal service first (sets up interface and HTTP redirect)
echo "Starting captive portal service..."
if systemctl start captive-portal.service; then
    echo "✓ Captive portal service started successfully"
else
    echo "⚠ Captive portal service failed, but continuing..."
fi
sleep 2

# Start PHP-FPM
echo "Starting PHP-FPM..."
systemctl start php${PHP_VERSION}-fpm
sleep 1

# Start services in correct order
echo "Starting nginx..."
systemctl start nginx
sleep 1

echo "Starting dnsmasq..."
if systemctl start dnsmasq; then
    echo "✓ dnsmasq started successfully"
else
    echo "✗ dnsmasq failed to start. Check: sudo journalctl -u dnsmasq -n 50"
fi
sleep 1

echo "Starting hostapd..."
if systemctl start hostapd; then
    echo "✓ hostapd started successfully"
    sleep 3
    # Verify AP is broadcasting
    if iw dev $WIFI_INTERFACE info | grep -q "ssid $AP_SSID"; then
        echo "✓ Access Point '$AP_SSID' is broadcasting"
    else
        echo "⚠ Access Point may not be broadcasting properly"
    fi
else
    echo "✗ hostapd failed to start. Check logs with: sudo journalctl -u hostapd -n 50"
    echo "  Common causes:"
    echo "  - WiFi interface in use by another service"
    echo "  - Driver incompatibility"
    echo "  Try: sudo rfkill unblock wifi"
fi

echo ""
echo "Services configuration complete!"
echo ""
echo "Testing configuration..."
echo "WiFi Interface Status:"
ip addr show $WIFI_INTERFACE | grep -E "inet |state" || echo "Interface info unavailable"
echo ""
echo "Active Services:"
systemctl is-active hostapd dnsmasq nginx
echo ""
