<?php

namespace CommerceGuys\Guzzle\Oauth2;

use CommerceGuys\Guzzle\Oauth2\GrantType\GrantTypeInterface;
use CommerceGuys\Guzzle\Oauth2\GrantType\RefreshTokenGrantTypeInterface;
use CommerceGuys\Guzzle\Oauth2\Middleware\RetryModifyRequestMiddleware;
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class Oauth2Client extends Client{

    /** @var AccessToken|null */
    protected $accessToken;
    /** @var AccessToken|null */
    protected $refreshToken;

    /** @var GrantTypeInterface */
    protected $grantType;
    /** @var RefreshTokenGrantTypeInterface */
    protected $refreshTokenGrantType;


    public function __construct($config=[]){

        $config['handler'] = $this->returnHandlers();

        parent::__construct($config);
    }

    /**
     * Set the middleware handlers for all requests using Oauth2
     *
     * @return HandlerStack|null
     */
    protected function returnHandlers(){
        // Create a handler stack that has all of the default middlewares attached
        $handler = HandlerStack::create();

        //Add the Authorization header to requests.
        $handler->push(Middleware::mapRequest(function (RequestInterface $request) {
            if ($this->getConfig('auth') == 'oauth2') {
                $token = $this->getAccessToken();

                if ($token !== null) {
                    var_dump("HEADER_ADDED");
                    var_dump($token);
                    $request = $request->withHeader('Authorization', 'Bearer ' . $token->getToken());
var_dump($request);
                    return $request;
                }
            }
            return $request;
        }),'add_oauth_header');

        $handler->before('add_oauth_header',$this->retry_modify_request(function ($retries, RequestInterface $request, ResponseInterface $response=null, $error=null){
                if($retries > 0){
                    return false;
                }
                if($response instanceof ResponseInterface){
                    if($response->getStatusCode() == 401){
                        return true;
                    }
                }
                return false;
            },
            function(RequestInterface $request, ResponseInterface $response){
                if($response instanceof ResponseInterface){
                    if($response->getStatusCode() == 401){
                        $token = $this->acquireAccessToken();
                        $this->setAccessToken($token, 'Bearer');

                        $modify['set_headers']['Authorization'] = 'Bearer ' . $token->getToken();
                        return Psr7\modify_request($request, $modify);
                    }
                }
                return $request;
            }
        ));

        return $handler;
    }

    /**
     * Retry Call after updating access token
     */

    function retry_modify_request(callable $decider, callable $requestModifier, callable $delay = null){
        return function (callable $handler) use ($decider, $requestModifier,  $delay) {
            return new RetryModifyRequestMiddleware($decider, $requestModifier, $handler, $delay);
        };
    }


    /**
     * Get a new access token.
     *
     * @return AccessToken|null
     */
    protected function acquireAccessToken()
    {
        $accessToken = null;

        if ($this->refreshTokenGrantType) {
            if ($this->refreshTokenGrantType->hasRefreshToken()) {
                $accessToken = $this->getToken($this->refreshTokenGrantType);
            }
        }

        if (!$accessToken && $this->grantType) {
            // Get a new access token.
            $accessToken = $this->getToken($this->grantType);
        }

        return $accessToken ?: null;
    }

    /**
     * Get the access token.
     *
     * @return AccessToken|null Oauth2 access token
     */
    public function getAccessToken()
    {
        if ($this->accessToken && $this->accessToken->isExpired()) {
            // The access token has expired.
            $this->accessToken = null;
        }

        if (null === $this->accessToken) {
            // Try to acquire a new access token from the server.
            $this->accessToken = $this->acquireAccessToken();
            if ($this->accessToken) {
                $this->refreshToken = $this->accessToken->getRefreshToken() ?: null;
            }
        }

        return $this->accessToken;
    }

    /**
     * Get the refresh token.
     *
     * @return AccessToken|null
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * Set the access token.
     *
     * @param AccessToken|string $accessToken
     * @param string             $type
     * @param int                $expires
     */
    public function setAccessToken($accessToken, $type = null, $expires = null)
    {
        if (is_string($accessToken)) {
            $accessToken = new AccessToken($accessToken, $type, ['expires' => $expires]);
        } elseif (!$accessToken instanceof AccessToken) {
            throw new \InvalidArgumentException('Invalid access token');
        }
        $this->accessToken = $accessToken;
    }

    /**
     * Set the refresh token.
     *
     * @param AccessToken|string $refreshToken The refresh token
     */
    public function setRefreshToken($refreshToken)
    {
        if (is_string($refreshToken)) {
            $refreshToken = new AccessToken($refreshToken, 'refresh_token');
        } elseif (!$refreshToken instanceof AccessToken) {
            throw new \InvalidArgumentException('Invalid refresh token');
        }
        $this->refreshToken = $refreshToken;
    }

    public function getToken($grantType)
    {
        $client = new Client();
        $config = $grantType->config;

        $form_params = $config;
        $form_params['grant_type'] = $grantType->grantType;
        unset($form_params['token_url'], $form_params['auth_location']);

        $requestOptions = [];

        if ($config['auth_location'] !== 'body') {
            $requestOptions['auth'] = [$config['client_id'], $config['client_secret']];
            unset($form_params['client_id'], $form_params['client_secret']);
        }

        $requestOptions['form_params'] = $form_params;

        if ($additionalOptions = $grantType->getAdditionalOptions()) {
            $requestOptions = array_merge_recursive($requestOptions, $additionalOptions);
        }

        try {
            $response = $client->post($config['token_url'], $requestOptions);
            $data = json_decode((string)$response->getBody(), true);
        }catch(ClientException $e){
            var_dump($e->getRequest());
            var_dump($e->getResponse());
            var_dump($e->getResponse()->getBody());
            die;
        }

        return new AccessToken($data['access_token'], $data['token_type'], $data);
    }

    public function setGrantType(GrantTypeInterface $grantType){
        $this->grantType = $grantType;
    }

    public function setRefreshTokenGrantType(RefreshTokenGrantTypeInterface $refreshTokenGrantType){
        $this->refreshTokenGrantType = $refreshTokenGrantType;
    }
}