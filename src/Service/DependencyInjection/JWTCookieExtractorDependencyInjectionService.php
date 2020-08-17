<?php

namespace App\Service\DependencyInjection;

use Symfony\Component\DependencyInjection\Exception\ParameterNotFoundException;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * Class JWTCookieExtractorDependencyInjectionService
 * @package App\Service\DependencyInjection
 */
class JWTCookieExtractorDependencyInjectionService
{
    /**
     * @var bool $authorizationHeaderExtractorEnabled
     */
    private bool $authorizationHeaderExtractorEnabled;

    /**
     * @var bool $httpOnlyCookieExtractorEnabled
     */
    private bool $httpOnlyCookieExtractorEnabled;

    /**
     * @var string $cookieName
     */
    private string $cookieName;

    /**
     * @var string $refreshCookieName
     */
    private string $refreshCookieName;

    /**
     * @var int $refreshTokenTtl
     */
    private int $refreshTokenTtl = 2592000;

    /**
     * @var string $refreshTokenParameterName
     */
    private string $refreshTokenParameterName = 'refresh_token';

    /**
     * JWTCookieExtractorDependencyInjectionService constructor.
     * @param ParameterBagInterface $params
     * @param string $refreshCookieName
     * @throws ParseException
     */
    public function __construct(ParameterBagInterface $params, string $refreshCookieName)
    {
        $lexikJwtConfig = Yaml::parseFile($params->get('kernel.project_dir').'/config/packages/lexik_jwt_authentication.yaml');
        $this->authorizationHeaderExtractorEnabled = !empty($lexikJwtConfig['lexik_jwt_authentication']['token_extractors']
            ['authorization_header']['enabled']);
        $this->httpOnlyCookieExtractorEnabled = !empty($lexikJwtConfig['lexik_jwt_authentication']['token_extractors']
            ['cookie']['enabled']);
        
        $this->cookieName = $params->get('app.jwt_cookie_name');
        $this->refreshCookieName = $refreshCookieName;

        try {
            $this->refreshTokenTtl = (int)$params->get('gesdinet_jwt_refresh_token.ttl');
            $this->refreshTokenParameterName = $params->get('gesdinet_jwt_refresh_token.token_parameter_name');
        } catch (ParameterNotFoundException $e) {
            // default values setted ...
        }
    }

    /**
     * @return boolean
     */
    public function isAuthorizationHeaderExtractorEnabled(): bool
    {
        return $this->authorizationHeaderExtractorEnabled;
    }

    /**
     * @return boolean
     */
    public function isHttpOnlyCookieExtractorEnabled(): bool
    {
        return $this->httpOnlyCookieExtractorEnabled;
    }

    /**
     * @return string
     */
    public function getCookieName(): string
    {
        return $this->cookieName;
    }

    /**
     * @return string
     */
    public function getRefreshCookieName(): string
    {
        return $this->refreshCookieName;
    }

    /**
     * @return int
     */
    public function getRefreshTokenTtl(): int
    {
        return $this->refreshTokenTtl;
    }

    /**
     * @return \DateTime
     */
    public function getDateTimeByRefreshTokenTtl(): \DateTime
    {
        return (new \DateTime())->add(new \DateInterval('PT'.$this->getRefreshTokenTtl().'S'));
    }

    /**
     * @return string
     */
    public function getRefreshTokenParameterName(): string
    {
        return $this->refreshTokenParameterName;
    }
}