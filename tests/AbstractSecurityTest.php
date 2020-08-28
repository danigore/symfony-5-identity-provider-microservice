<?php

namespace App\Tests;

use App\Security\UserInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\InvalidPayloadException;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTDecodeFailureException;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\UserNotFoundException;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Authentication\Token\PreAuthenticationJWTUserToken;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * Class AbstractSecurityTest
 * @package App\Tests
 */
abstract class AbstractSecurityTest extends AbstractFunctionalTest
{
    /**
     * Get the logged in User from the JWTTokenAuthenticator.
     * 
     * Additionally: There are some problems with the original symfony security.token_storage, what
     * probably can be traced from the default doctrine's app_user_provider ...
     * You can get the token and from that the original User entity immediately after the login,
     * and this is may okay, but even worst that, the original User entity still available through this service,
     * after the token expiration!
     * The AuthorizationTestRoutesControllerTest(s) are prove it, it has no effect to the authorization checks,
     * the isGranted method IN A CONTROLLER returns false, when the token expired,
     * but directly the entity accessable later on.
     * 
     * Special funny, after a token refresh the (security.token_storage)->getToken() returns null,
     * so there is no token, and logically no UserInterface imlemented object anymore.
     * 
     * Across the lexik_jwt_authentication.jwt_token_authenticator you can get the databaseless User object,
     * (originally Lexik\Bundle\JWTAuthenticationBundle\Security\User\JWTUser) from JWT,
     * and this object is not accessable after the token expiration.
     * 
     * @return UserInterface|null
     * @throws \InvalidArgumentException If preAuthToken is not of the good type
     * @throws InvalidPayloadException   If the user identity field is not a key of the payload
     * @throws UserNotFoundException     If no user can be loaded from the given token
     */
    protected function getUser(): ?UserInterface
    {
        $rawToken = $this->getToken();
        if (!$rawToken) {
            return null;
        }

        $tokenDecoder = parent::$container->get('lexik_jwt_authentication.encoder.lcobucci');
        $JWTTokenAuthenticator = parent::$container->get('lexik_jwt_authentication.jwt_token_authenticator');
        
        try {
            $payload = $tokenDecoder->decode($rawToken);
        } catch (JWTDecodeFailureException $e) {
            return null;
        }

        $token = new PreAuthenticationJWTUserToken($rawToken);
        $token->setPayload($payload);

        $user = $JWTTokenAuthenticator->getUser(
            $token,
            parent::$container->get('security.user.provider.concrete.jwt')
        );
        
        if (!$user instanceof UserInterface) {
            return null;
        }

        return $user;
    }

    /**
     * @return boolean
     * @throws ParseException
     */
    protected function authorizationHeaderTypeTokenExtractorIsEnabled(): bool
    {
        $lexikJwtConfig = Yaml::parseFile(parent::$kernel->getContainer()
            ->getParameter('kernel.project_dir').'/config/packages/lexik_jwt_authentication.yaml');
            
        return !empty($lexikJwtConfig['lexik_jwt_authentication']['token_extractors']
            ['authorization_header']['enabled']);
    }

    /**
     * @return string|null
     */
    protected function getToken(): ?string
    {
        if ($this->authorizationHeaderTypeTokenExtractorIsEnabled()) {
            return $this->getJsonResponseContentValue('token');
        }

        $cookie = $this->client->getCookieJar()->get(parent::$kernel->getContainer()
            ->getParameter('app.jwt_cookie_name'));

        if (!$cookie instanceof Cookie) {
            return null;
        }

        return $cookie->getValue();
    }

    /**
     * Simulate a login request by ROLE
     *
     * @param string $role
     * @return void
     */
    protected function simulateLogin(string $role = 'ROLE_USER'): void
    {
        $this->output->writeln("\n<info>Simulate a login with $role ...</info>");
        $this->client->request('POST', '/login_check', [], [], [
            'CONTENT_TYPE' => 'application/json'
        ], json_encode($this->getUserCredentialsByRole($role)));
    }

    /**
     * @param string $token
     * @return array
     */
    protected function getAuthHeaders(?string $token = null): array
    {
        if (!$token) {
            $token = $this->getJsonResponseContentValue('token');
        }

        return [
            'HTTP_AUTHORIZATION' => "bearer {$token}",
            'CONTENT_TYPE' => 'application/ld+json',
            'HTTP_ACCEPT' => 'application/ld+json'
        ];
    }

    /**
     * @param string $uri
     * @param string $method
     * @return void
     */
    protected function accessDeniedWithoutLoginTest(string $uri, string $method = 'GET'): void
    {
        $this->output->writeln("<info>Simulate an invalid request without JWT token ...</info>");
        $exceptionThrown = false;
        try {
            $this->client->request($method, $uri);
        } catch (AccessDeniedException $e) {
            $exceptionThrown = true;
        }
        $this->assertSame(true, $exceptionThrown);
    }

    /**
     * @param string $uri
     * @param string $role
     * @param string $method
     * @return void
     */
    protected function accessDeniedForRoleTest(string $uri, string $role = 'ROLE_USER', string $method = 'GET'): void
    {
        $this->simulateLogin($role);

        $this->output->writeln("<info>Simulate an invalid request with $role ...</info>");
        $exceptionThrown = false;
        try {
            if ($this->authorizationHeaderTypeTokenExtractorIsEnabled()) {
                $this->client->request($method, $uri, [], [], $this->getAuthHeaders());
            } else {
                $this->client->request($method, $uri);
            }
        } catch (AccessDeniedException $e) {
            $exceptionThrown = true;
        }
        $this->assertSame(true, $exceptionThrown);
    }

    /**
     * @param string|null $role
     * @return array
     */
    private function getUserCredentialsByRole(string $role): array
    {
        switch ($role) {
            case 'ROLE_ADMIN': return ['username' => 'dextermorgan@cvlt.dev', 'password' => 'Debra'];
            default: return ['username' => 'eleven@cvlt.dev', 'password' => 'Eggo'];
        }
    }

    /**
     * Refresh the Json Web Token
     *
     * @return void
     */
    protected function refreshTheToken(): void
    {
        if ($this->authorizationHeaderTypeTokenExtractorIsEnabled()) {
            $refreshTokenParameterName = parent::$kernel->getContainer()
            ->getParameter('gesdinet_jwt_refresh_token.token_parameter_name');
            $refreshToken = $this->getJsonResponseContentValue(parent::$kernel->getContainer()
                ->getParameter('gesdinet_jwt_refresh_token.token_parameter_name'));

            $this->client->request('UPDATE', '/token/refresh', [], [], [
                'CONTENT_TYPE' => 'application/json'
            ], json_encode([$refreshTokenParameterName => $refreshToken]));
        } else {
            $this->client->request('UPDATE', '/token/refresh');
        }
    }
}