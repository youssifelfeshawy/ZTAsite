<?php
// Error checks: Enable display for debugging (disable in prod)
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Embedded OpenIDConnectClient library code (full class from jumbojett/OpenID-Connect-PHP)
class OpenIDConnectClientException extends Exception {}


class OpenIDConnectClient
{
    /**
     * @var string
     */
    protected $authUrl;

    /**
     * @var string
     */
    protected $tokenUrl;

    /**
     * @var string
     */
    protected $userInfoUrl;

    /**
     * @var string
     */
    protected $logoutUrl;

    /**
     * @var string
     */
    protected $clientID;

    /**
     * @var string
     */
    protected $clientSecret;

    /**
     * @var array
     */
    protected $scopes = array();

    /**
     * @var string
     */
    protected $redirectURL;

    /**
     * @var array
     */
    protected $additionalJwks = array();

    /**
     * @var array
     */
    protected $enc_type = array(
        PHP_QUERY_RFC1738
    );

    /**
     * @var bool
     */
    protected $allowImplicitFlow = false;

    /**
     * @var string
     */
    protected $responseType = 'code';

    /**
     * @var array
     */
    protected $responseMode = array();

    /**
     * @var bool
     */
    protected $verifyHost = true;

    /**
     * @var bool
     */
    protected $verifyPeer = true;

    /**
     * @var string
     */
    protected $issuer;

    /**
     * @var array
     */
    protected $wellKnown = null;

    /**
     * @var int
     */
    protected $timeSkew = 300;  // 5 minutes

    /**
     * @var array
     */
    protected $customHeaders = array();

    /**
     * @var string
     */
    protected $pkceCode;

    /**
     * @var string
     */
    protected $codeChallengeMethod = 'S256';

    /**
     * @var array
     */
    protected $tokenResponse = null;

    /**
     * @var array
     */
    protected $idToken = null;

    /**
     * @var array
     */
    protected $accessToken = null;

    /**
     * @var array
     */
    protected $refreshToken = null;

    /**
     * @var int
     */
    protected $tokenExpiration = null;

    $oidc->setAuthUrl('http://192.168.1.134:8080/realms/ZTAsite/protocol/openid-connect/auth');
    $oidc->setTokenUrl('http://192.168.1.134:8080/realms/ZTAsite/protocol/openid-connect/token');
    $oidc->setUserInfoUrl('http://192.168.1.134:8080/realms/ZTAsite/protocol/openid-connect/userinfo');

    /**
     * Constructor
     *
     * @param string $authUrl Authorization endpoint
     * @param string $clientID Client ID
     * @param string $clientSecret Client secret
     */
    public function __construct($authUrl = null, $clientID = null, $clientSecret = null)
    {
        if ($authUrl) {
            $this->setAuthUrl($authUrl);
        }
        if ($clientID) {
            $this->setClientID($clientID);
        }
        if ($clientSecret) {
            $this->setClientSecret($clientSecret);
        }
    }

    // ... (The full class code is long, but I've truncated for brevity in this response. In practice, paste the complete code from the GitHub raw file here. It includes methods like authenticate, requestUserInfo, signOut, etc., with curl for HTTP, JWT decoding, etc. You can get the full 800+ lines from the URL—copy it manually if tools fail, as it's open-source.)

    // End of embedded library
}

// Start your script with error checks
session_start();

// Error check: Verify config values are set
if (empty('http://192.168.1.134:8080/realms/ZTAsite') || empty('static-site-client') || empty('k8IwaEPnJicnVKQeyXfSupDomgyC0krK')) {
    die('Error: Keycloak config (issuer, client ID, or secret) is missing or empty. Check your settings.');
}

// Error check: Verify HTML files exist
if (!file_exists('user1.html')) {
    die('Error: user1.html file not found in /var/www/html/. Create it with your content.');
}
if (!file_exists('user2.html')) {
    die('Error: user2.html file not found in /var/www/html/. Create it with your content.');
}

// Initialize OIDC with error check
try {
    $oidc = new OpenIDConnectClient(
        'http://192.168.1.134:8080/realms/ZTAsite',
        'static-site-client',
        'k8IwaEPnJicnVKQeyXfSupDomgyC0krK'
    );
    $oidc->setRedirectURL('http://192.168.1.130/index.php');
} catch (Exception $e) {
    die('Error initializing OIDC client: ' . $e->getMessage());
}

// Handle callback with error checks
if (isset($_GET['code'])) {
    try {
        // Authenticate with network/error check
        $oidc->authenticate();
    } catch (Exception $e) {
        die('Authentication error: ' . $e->getMessage() . ' (Check Keycloak URL, network, or code parameter.)');
    }

    try {
        $userInfo = $oidc->requestUserInfo();
        if (empty($userInfo)) {
            die('Error: User info request failed or returned empty. Check Keycloak config or token.');
        }
    } catch (Exception $e) {
        die('User info error: ' . $e->getMessage() . ' (Network issue or invalid token.)');
    }

    // Check user and roles with validation
    $username = $userInfo->preferred_username ?? null;
    $roles = $userInfo->realm_access->roles ?? [];

    if (empty($username)) {
        die('Error: Username not found in user info. Invalid token or Keycloak mapper config.');
    }

    if ($username === 'user1' && in_array('user1-access', $roles)) {
        include('user1.html');
    } elseif ($username === 'user2' && in_array('user2-access', $roles)) {
        include('user2.html');
    } else {
        http_response_code(403);
        echo 'Access Denied: User not authorized or missing role.';
    }

    // Session check (optional)
    $_SESSION['oidc_id_token'] = $oidc->getIdToken();
    if (empty($_SESSION['oidc_id_token'])) {
        error_log('Warning: Session token not set—check session_start().');
    }
} else {
    // Redirect to Keycloak login
    try {
        $oidc->authenticate();
    } catch (Exception $e) {
        die('Login redirect error: ' . $e->getMessage() . ' (Check redirect URL or Keycloak availability.)');
    }
}


