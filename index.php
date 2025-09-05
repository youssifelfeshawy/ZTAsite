<?php
require __DIR__ . '/vendor/autoload.php';

use Jumbojett\OpenIDConnectClient;

session_start();

// Keycloak config
$oidc = new OpenIDConnectClient(
    'http://192.168.1.134:8080/realms/ZTAsite',  // Issuer URL
    'static-site-client',  // Client ID from Keycloak
    'k8IwaEPnJicnVKQeyXfSupDomgyC0krK'   // Client secret from Keycloak
);
$oidc->setRedirectURL('http://192.168.1.130/ZTAsite/index.php');  // Callback to itself

// Handle callback
if (isset($_GET['code'])) {
    try {
        $oidc->authenticate();  // Handle code, get tokens
        $userInfo = $oidc->requestUserInfo();  // Get user details

        // Check user and roles from token
        $username = $userInfo->preferred_username;
        $roles = $userInfo->realm_access->roles ?? [];

        if ($username === 'user1' && in_array('user1-access', $roles)) {
            include('user1.html');
        } elseif ($username === 'user2' && in_array('user2-access', $roles)) {
            include('user2.html');
        } else {
            http_response_code(403);
            echo 'Access Denied';
        }

        // Store for session (optional)
        $_SESSION['oidc_id_token'] = $oidc->getIdToken();
    } catch (Exception $e) {
        echo 'Error: ' . $e->getMessage();
    }
} else {
    // Redirect to Keycloak login
    $oidc->authenticate();
}
