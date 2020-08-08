<?php

namespace App\Service\DependencyInjection;

use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * Class LexikJWTAuthenticationDependencyInjectionService
 * @package App\Service\DependencyInjection
 */
class LexikJWTAuthenticationDependencyInjectionService
{
    private bool $authorizationHeaderExtractorEnabled;
    private bool $httpOnlyCookieExtractorEnabled;
    private string $cookieName = 'BEARER';

    /**
     * LexikJWTAuthenticationDependencyInjectionService constructor.
     * @param ParameterBagInterface $params
     * @throws ParseException
     */
    public function __construct(ParameterBagInterface $params)
    {
        $lexikJwtConfig = Yaml::parseFile($params->get('kernel.project_dir').'/config/packages/lexik_jwt_authentication.yaml');
        $this->authorizationHeaderExtractorEnabled = !empty($lexikJwtConfig['lexik_jwt_authentication']['token_extractors']
            ['authorization_header']['enabled']);
        $this->httpOnlyCookieExtractorEnabled = !empty($lexikJwtConfig['lexik_jwt_authentication']['token_extractors']
            ['cookie']['enabled']);
        if (!empty($lexikJwtConfig['lexik_jwt_authentication']['token_extractors']['cookie']['name'])) {
            $this->cookieName = $lexikJwtConfig['lexik_jwt_authentication']['token_extractors']['cookie']['name'];
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
}