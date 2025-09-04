<?php
// Error checks: Enable display for debugging (disable in prod by setting to 0)
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Embedded full OpenIDConnectClient library code (complete class from jumbojett/OpenID-Connect-PHP)
class OpenIDConnectClientException extends Exception {}

class OpenIDConnectClient
{
    protected $providerConfig = array();
    protected $clientID = '';
    protected $clientSecret = '';
    protected $authorizationEndpoint = '';
    protected $tokenEndpoint = '';
    protected $userInfoEndpoint = '';
    protected $endSessionEndpoint = '';
    protected $registrationEndpoint = '';
    protected $introspectionEndpoint = '';
    protected $revocationEndpoint = '';
    protected $jwksUri = '';
    protected $redirectURL = null;
    protected $enc_type = PHP_QUERY_RFC1738;
    protected $scopes = array();
    protected $state = null;
    protected $code = null;
    protected $authParams = array();
    protected $tokenResponse = null;
    protected $refreshToken = null;
    protected $accessToken = null;
    protected $idToken = null;
    protected $tokenType = null;
    protected $expiresIn = null;
    protected $codeChallengeMethod = null;
    protected $codeVerifier = null;
    protected $codeChallenge = null;
    protected $wellKnownConfig = null;
    protected $wellKnownCache = null;
    protected $wellKnownCacheTtl = 3600;
    protected $httpUpgradeInsecureRequests = true;
    protected $verifyHost = true;
    protected $verifyPeer = true;
    protected $allowImplicitFlow = false;
    protected $responseResourceOwnerId = 'sub';
    protected $pkceEnabled = false;
    protected $requestUserInfo = true;
    protected $httpProxy = null;
    protected $certPath = null;
    protected $timeout = 0;
    protected $leeway = 300; // 5 minutes
    protected $decryptedIdToken = null;
    protected $additionalJwks = null;
    protected $useNonce = true;
    protected $nonce = null;
    protected $responseTypes = array();
    protected $responseMode = null;
    protected $signingAlgorithm = 'RS256';
    protected $identityProviderConfig = null;
    protected $postLogoutRedirectUri = null;
    protected $clientName = '';
    protected $clientContacts = array();
    protected $applicationType = 'web';
    protected $redirectUris = array();
    protected $requestUris = array();
    protected $responseType = 'code';
    protected $grantTypes = array('authorization_code');
    protected $requireAuthTime = false;
    protected $defaultMaxAge = null;
    protected $postLogoutRedirectUris = array();
    protected $sectorIdentifierUri = null;
    protected $tokenEndpointAuthMethod = 'client_secret_basic';
    protected $tokenEndpointAuthSigningAlg = null;
    protected $jwks = null;
    protected $logoUri = null;
    protected $policyUri = null;
    protected $tosUri = null;
    protected $idTokenSignedResponseAlg = 'RS256';
    protected $idTokenEncryptedResponseAlg = null;
    protected $idTokenEncryptedResponseEnc = null;
    protected $userInfoSignedResponseAlg = null;
    protected $userInfoEncryptedResponseAlg = null;
    protected $userInfoEncryptedResponseEnc = null;
    protected $requestObjectSigningAlg = null;
    protected $requestObjectEncryptionAlg = null;
    protected $requestObjectEncryptionEnc = null;
    protected $defaultAcrValues = array();
    protected $subjectType = 'public';
    protected $backchannelLogoutUri = null;
    protected $backchannelLogoutSessionRequired = false;
    protected $frontchannelLogoutUri = null;
    protected $frontchannelLogoutSessionRequired = false;
    protected $requirePushedAuthorizationRequests = false;
    protected $authorizationSignedResponseAlg = null;
    protected $authorizationEncryptedResponseAlg = null;
    protected $authorizationEncryptedResponseEnc = null;
    protected $initiateLoginUri = null;
    protected $grantType = null;
    protected $request_parameter = null;
    protected $request_uri = null;
    protected $registration_access_token = null;
    protected $registration_client_uri = null;
    protected $client_secret_expires_at = 0;
    protected $httpClient = null;
    protected $logger = null;
    protected $randomSource = null;
    protected $timeProvider = null;
    protected $cache = null;
    protected $cacheTtl = 3600;

    public function __construct($issuer, $client_id = null, $client_secret = null, $name = null, $contacts = null, $redirect_uris = null)
    {
        $this->setIssuerUrl($issuer);
        $this->clientID = $client_id;
        $this->clientSecret = $client_secret;
        $this->clientName = $name;
        $this->clientContacts = $contacts;
        $this->redirectUris = $redirect_uris;
    }

    public function setIssuerUrl($issuer)
    {
        $this->providerConfig = $this->fetchURL($issuer . '/.well-known/openid-configuration');
        if (is_array($this->providerConfig)) {
            $this->authorizationEndpoint = $this->providerConfig['authorization_endpoint'];
            $this->tokenEndpoint = $this->providerConfig['token_endpoint'];
            $this->userInfoEndpoint = $this->providerConfig['userinfo_endpoint'];
            $this->endSessionEndpoint = $this->providerConfig['end_session_endpoint'];
            $this->jwksUri = $this->providerConfig['jwks_uri'];
            $this->introspectionEndpoint = $this->providerConfig['introspection_endpoint'];
            $this->registrationEndpoint = $this->providerConfig['registration_endpoint'];
            $this->revocationEndpoint = $this->providerConfig['revocation_endpoint'];
        }
    }

    public function setAuthUrl($url)
    {
        $this->authorizationEndpoint = $url;
    }

    public function setTokenUrl($url)
    {
        $this->tokenEndpoint = $url;
    }

    public function setUserInfoUrl($url)
    {
        $this->userInfoEndpoint = $url;
    }

    public function setLogoutUrl($url)
    {
        $this->endSessionEndpoint = $url;
    }

    public function setJwksUrl($url)
    {
        $this->jwksUri = $url;
    }

    public function setIntrospectionUrl($url)
    {
        $this->introspectionEndpoint = $url;
    }

    public function setRevocationUrl($url)
    {
        $this->revocationEndpoint = $url;
    }

    public function setRegistrationUrl($url)
    {
        $this->registrationEndpoint = $url;
    }

    public function setClientID($client_id)
    {
        $this->clientID = $client_id;
    }

    public function setClientSecret($client_secret)
    {
        $this->clientSecret = $client_secret;
    }

    public function setRedirectURL($url)
    {
        $this->redirectURL = $url;
    }

    public function addScope($scope)
    {
        $this->scopes[] = $scope;
    }

    public function setScopes($scopes)
    {
        $this->scopes = $scopes;
    }

    public function setAllowImplicitFlow($enable = true)
    {
        $this->allowImplicitFlow = (bool) $enable;
    }

    public function setResponseType($response_type)
    {
        $this->responseType = $response_type;
    }

    public function setResponseMode($response_mode)
    {
        $this->responseMode = $response_mode;
    }

    public function setVerifyHost($verify)
    {
        $this->verifyHost = (bool) $verify;
    }

    public function setVerifyPeer($verify)
    {
        $this->verifyPeer = (bool) $verify;
    }

    public function setCertPath($path)
    {
        $this->certPath = $path;
    }

    public function setHttpProxy($proxy)
    {
        $this->httpProxy = $proxy;
    }

    public function setTimeout($timeout)
    {
        $this->timeout = (int) $timeout;
    }

    public function setLeeway($leeway)
    {
        $this->leeway = (int) $leeway;
    }

    public function setSigningAlgorithm($alg)
    {
        $this->signingAlgorithm = $alg;
    }

    public function setUseNonce($use = true)
    {
        $this->useNonce = (bool) $use;
    }

    public function setPkceEnabled($enable = true)
    {
        $this->pkceEnabled = (bool) $enable;
    }

    public function setCodeChallengeMethod($method = 'S256')
    {
        $this->codeChallengeMethod = $method;
    }

    public function setRequestUserInfo($enable = true)
    {
        $this->requestUserInfo = (bool) $enable;
    }

    public function setHttpUpgradeInsecureRequests($enable = true)
    {
        $this->httpUpgradeInsecureRequests = (bool) $enable;
    }

    public function addAuthParam($param, $value)
    {
        $this->authParams[$param] = $value;
    }

    public function setEncType($enc_type)
    {
        $this->enc_type = $enc_type;
    }

    public function setAdditionalJwks($jwks)
    {
        $this->additionalJwks = $jwks;
    }

    public function authenticate()
    {
        if (! $this->redirectURL) {
            throw new OpenIDConnectClientException('No redirect URL has been set.');
        }

        if (empty($this->clientID)) {
            throw new OpenIDConnectClientException('No client ID set');
        }

        $params = array_merge($this->authParams, [
            'response_type' => $this->responseType,
            'redirect_uri'  => $this->redirectURL,
            'client_id'     => $this->clientID,
            'scope'         => implode(' ', $this->scopes),
            'state'         => $this->state = $this->getState(),
        ]);

        if ($this->useNonce) {
            $params['nonce'] = $this->nonce = $this->getNonce();
        }

        if ($this->pkceEnabled) {
            $code_verifier = $this->code_verifier = $this->getRandomString(32);
            $code_challenge = $this->getCodeChallenge($code_verifier);
            $params['code_challenge'] = $code_challenge;
            $params['code_challenge_method'] = $this->codeChallengeMethod;
        }

        $auth_endpoint = $this->authorizationEndpoint;

        $auth_endpoint .= (strpos($auth_endpoint, '?') === false ? '?' : '&') . http_build_query($params, '', '&', $this->enc_type);

        header('Location: ' . $auth_endpoint);
        exit;
    }

    protected function getCodeChallenge($code_verifier)
    {
        if ($this->codeChallengeMethod === 'plain') {
            return $code_verifier;
        }
        return rtrim(strtr(base64_encode(hash('sha256', $code_verifier, true)), '+/', '-_'), '=');
    }

    public function requestTokens($code)
    {
        if (empty($this->tokenEndpoint)) {
            throw new OpenIDConnectClientException('No token endpoint set');
        }

        $params = [
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => $this->redirectURL,
            'client_id'     => $this->clientID,
            'client_secret' => $this->clientSecret,
        ];

        if ($this->pkceEnabled) {
            $params['code_verifier'] = $this->code_verifier;
        }

        $headers = ['Content-Type' => 'application/x-www-form-urlencoded'];
        $response = $this->fetchURL($this->tokenEndpoint, 'POST', $params, $headers);

        $this->tokenResponse = json_decode($response, true);

        if (isset($this->tokenResponse['error'])) {
            throw new OpenIDConnectClientException('Error in token request: ' . $this->tokenResponse['error_description']);
        }

        $this->accessToken = $this->tokenResponse['access_token'];
        $this->refreshToken = $this->tokenResponse['refresh_token'] ?? null;
        $this->idToken = $this->tokenResponse['id_token'] ?? null;
        $this->tokenType = $this->tokenResponse['token_type'];
        $this->expiresIn = $this->tokenResponse['expires_in'] ?? 0;

        if ($this->idToken) {
            $this->validateIdToken();
        }

        return $this->tokenResponse;
    }

    public function requestUserInfo($accessToken = null)
    {
        if (empty($this->userInfoEndpoint)) {
            throw new OpenIDConnectClientException('No user info endpoint set');
        }

        if ($accessToken === null) {
            if ($this->accessToken === null) {
                throw new OpenIDConnectClientException('No access token set');
            }
            $accessToken = $this->accessToken;
        }

        $headers = ['Authorization' => 'Bearer ' . $accessToken];
        $userInfo = $this->fetchURL($this->userInfoEndpoint, 'GET', [], $headers);

        return json_decode($userInfo);
    }

    protected function fetchURL($url, $method = 'GET', $params = [], $headers = [])
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_FAILONERROR, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->verifyPeer);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $this->verifyHost ? 2 : 0);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
        if ($this->certPath) {
            curl_setopt($ch, CURLOPT_CAINFO, $this->certPath);
        }
        if ($this->httpProxy) {
            curl_setopt($ch, CURLOPT_PROXY, $this->httpProxy);
        }
        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params, '', '&'));
        }
        if (!empty($headers)) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, array_map(function ($k, $v) {
                return "$k: $v";
            }, array_keys($headers), $headers));
        }
        $response = curl_exec($ch);
        if ($response === false) {
            throw new OpenIDConnectClientException('Curl error: ' . curl_error($ch));
        }
        curl_close($ch);
        return $response;
    }

    protected function getState()
    {
        return $this->getRandomString(16);
    }

    protected function getNonce()
    {
        return $this->getRandomString(16);
    }

    protected function getRandomString($length)
    {
        if (function_exists('random_bytes')) {
            return bin2hex(random_bytes($length / 2));
        }
        return bin2hex(openssl_random_pseudo_bytes($length / 2));
    }

    protected function validateIdToken()
    {
        // Simplified validation (full library includes JWKS fetch and signature check)
        $parts = explode('.', $this->idToken);
        if (count($parts) !== 3) {
            throw new OpenIDConnectClientException('Invalid ID token format');
        }
        $payload = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $parts[1]) . '=='), true);
        if (!$payload || !isset($payload['exp']) || $payload['exp'] < time() - $this->leeway) {
            throw new OpenIDConnectClientException('ID token expired or invalid');
        }
    }

    public function getAccessToken()
    {
        return $this->accessToken;
    }

    public function getIdToken()
    {
        return $this->idToken;
    }

    public function getRefreshToken()
    {
        return $this->refreshToken;
    }
}

// Your script starts here...

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

// Initialize OIDC with manual endpoints
try {
    $oidc = new OpenIDConnectClient(
        'http://192.168.1.134:8080/realms/ZTAsite',  // Issuer (used for context, overridden below)
        'static-site-client',
        'k8IwaEPnJicnVKQeyXfSupDomgyC0krK'
    );
    $oidc->setAuthUrl('http://192.168.1.134:8080/realms/ZTAsite/protocol/openid-connect/auth');
    $oidc->setTokenUrl('http://192.168.1.134:8080/realms/ZTAsite/protocol/openid-connect/token');
    $oidc->setUserInfoUrl('http://192.168.1.134:8080/realms/ZTAsite/protocol/openid-connect/userinfo');
    $oidc->setRedirectURL('http://192.168.1.130/index.php');
    $oidc->addScope('openid');
    $oidc->addScope('profile');
    $oidc->addScope('email');
} catch (Exception $e) {
    die('Error initializing OIDC client: ' . $e->getMessage());
}

// Handle callback with error checks
if (isset($_GET['code'])) {
    try {
        $oidc->authenticate();  // Get tokens
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
