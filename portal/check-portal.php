<?php
// check-portal.php - Handle captive portal detection checks
// This script checks if the user has accepted terms and returns appropriate responses

session_start();

// Check if user has accepted terms and has internet access
$clientIP = $_SERVER['REMOTE_ADDR'];
$hasAccepted = isset($_SESSION['portal_accepted']) && $_SESSION['portal_accepted'] === true;

// Also check if client has iptables rule (actually has internet)
$hasInternetAccess = false;
if ($hasAccepted) {
    exec("sudo /usr/local/bin/check-internet-access.sh " . escapeshellarg($clientIP), $output, $return_code);
    $hasInternetAccess = ($return_code === 0);
}

// If user has accepted and has internet access, return success codes
if ($hasAccepted && $hasInternetAccess) {
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
