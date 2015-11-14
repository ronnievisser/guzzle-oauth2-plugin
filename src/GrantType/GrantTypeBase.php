<?php

namespace CommerceGuys\Guzzle\Oauth2\GrantType;

use CommerceGuys\Guzzle\Oauth2\AccessToken;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\ClientException;

class GrantTypeBase implements GrantTypeInterface
{

    /** @var array Configuration settings */
    public $config;

    /** @var string */
    public $grantType = '';

    /**
     * @param array $config
     */
    public function __construct(array $config = [])
    {
        $this->config = array_merge($this->getDefaults(), $config);
    }

    /**
     * Get default configuration items.
     *
     * @return array
     */
    protected function getDefaults()
    {
        return [
            'client_secret' => '',
            'scope' => '',
            'token_url' => 'oauth2/token',
            'auth_location' => 'headers',
            'body_type' => 'form_params',
        ];
    }

    /**
     * Get required configuration items.
     *
     * @return string[]
     */
    protected function getRequired()
    {
        return ['client_id'];
    }

    /**
     * Get additional options, if any.
     *
     * @return array|null
     */
    public function getAdditionalOptions()
    {
        return null;
    }
}