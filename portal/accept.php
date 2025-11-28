<?php
// accept.php - Handle portal agreement acceptance

// Start session to track accepted users
session_start();

// Get client MAC address (if available)
function getClientMAC() {
    $mac = shell_exec("arp -a " . $_SERVER['REMOTE_ADDR'] . " | awk '{print $4}'");
    return trim($mac);
}

// Log acceptance
function logAcceptance($ip, $mac, $userAgent) {
    $logFile = '/var/log/captive-portal.log';
    $timestamp = date('Y-m-d H:i:s');
    $logEntry = "$timestamp | IP: $ip | MAC: $mac | User-Agent: $userAgent\n";
    file_put_contents($logFile, $logEntry, FILE_APPEND);
}

// Check if form was submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['agree'])) {
    $clientIP = $_SERVER['REMOTE_ADDR'];
    $clientMAC = getClientMAC();
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    
    // Mark this session as accepted
    $_SESSION['portal_accepted'] = true;
    $_SESSION['accepted_time'] = time();
    $_SESSION['client_ip'] = $clientIP;
    
    // Log the acceptance
    logAcceptance($clientIP, $clientMAC, $userAgent);
    
    // Add client to accepted list (stored in file)
    $acceptedFile = '/tmp/accepted_clients.txt';
    file_put_contents($acceptedFile, $clientIP . "\n", FILE_APPEND);
    
    // Grant internet access by adding iptables rule
    // This adds the client IP to the allowed list
    $command = "sudo /usr/local/bin/grant-internet-access.sh " . escapeshellarg($clientIP);
    exec($command, $output, $return_code);
    
    // Return success with redirect to dismiss captive portal
    http_response_code(200);
    header('Content-Type: application/json');
    echo json_encode([
        'status' => 'success',
        'message' => 'Access granted',
        'ip' => $clientIP,
        'granted' => ($return_code === 0),
        'redirect' => '/portal-dismissed.html'
    ]);
    exit;
}

// If accessed directly without POST
http_response_code(400);
echo json_encode([
    'status' => 'error',
    'message' => 'Invalid request'
]);
?>
