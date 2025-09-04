<?php
require 'vendor/autoload.php';  // From composer

use Maicol07\OIDCClient\OIDCClient;

session_start();

// Keycloak config (adjust IPs/ports)
$client = new OIDCClient([
    'client_id' => 'static-site-client',
    'client_secret' => 'your_client_secret',  // From Keycloak
    'redirect_uri' => 'http://192.168.1.130/callback',
    'auth_endpoint' => 'http://192.168.1.134:8080/realms/org-realm/protocol/openid-connect/auth',
    'token_endpoint' => 'http://192.168.1.134:8080/realms/org-realm/protocol/openid-connect/token',
    'userinfo_endpoint' => 'http://192.168.1.134:8080/realms/org-realm/protocol/openid-connect/userinfo',
    'end_session_endpoint' => 'http://192.168.1.134:8080/realms/org-realm/protocol/openid-connect/logout',
    'scopes' => ['openid', 'profile', 'email']  // Include roles
]);

// Handle callback from Keycloak
if (isset($_GET['code'])) {
    try {
        $token = $client->handleCallback();  // Get tokens
        $userInfo = $client->getUserInfo();  // Get user details/roles

        // Check user and roles
        $username = $userInfo['preferred_username'];
        $roles = $userInfo['realm_access']['roles'] ?? [];

        if ($username === 'user1' && in_array('user1-access', $roles)) {
            include('user1.html');  // Embed user1 HTML here
        } elseif ($username === 'user2' && in_array('user2-access', $roles)) {
            include('user1.html');  // Embed user2 HTML here
        } else {
            http_response_code(403);
            echo 'Access Denied';
        }

        // Store token for session
        $_SESSION['oidc_token'] = $token;
    } catch (Exception $e) {
        echo 'Error: ' . $e->getMessage();
    }
} else {
    // Redirect to Keycloak login
    $client->authenticate();
}
