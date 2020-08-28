<?php

namespace App\Tests\Subscriber;

use App\Tests\AbstractSecurityTest;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException;

/**
 * Class TokenRefresherSubscriberTest
 * @package App\Tests\Subscriber
 */
class TokenRefresherSubscriberTest extends AbstractSecurityTest
{
    /**
     * @return void
     */
    public function testSetRefreshTokenCookie(): void
    {
        $this->runCommand('doctrine:fixtures:load --append --group=UserFixtures');
        $this->output->writeln("\r\n<info>Test the refresh token cookie setted:</info>");
        $this->client->catchExceptions(false);

        $this->simulateLogin('ROLE_ADMIN');

        $cookie = $this->client->getCookieJar()->get('BEARER_REFRESH');

        if ($this->authorizationHeaderTypeTokenExtractorIsEnabled()) {
            $this->assertSame(null, $cookie);
        } else {
            $this->assertSame(true, $cookie instanceof Cookie);
        }
    }

    /**
     * @return void
     */
    public function testRemoveRefreshTokenFromResponse(): void
    {
        $this->runCommand('doctrine:fixtures:load --append --group=UserFixtures');
        $this->output->writeln("\r\n<info>Test the refresh token removed from the response:</info>");
        $this->client->catchExceptions(false);

        $this->simulateLogin('ROLE_ADMIN');

        $token = $this->getJsonResponseContentValue(parent::$kernel->getContainer()
            ->getParameter('gesdinet_jwt_refresh_token.token_parameter_name'));

        if ($this->authorizationHeaderTypeTokenExtractorIsEnabled()) {
            $this->assertSame(true, !empty($token) && is_string($token));
        } else {
            $this->assertSame(null, $token);

            $this->client->request('GET', '/authorization-tests/admin-role');

            $this->output->writeln("\n<info>... Check again the refresh token is removed, after a valid request on an authorized route ...</info>");
            $this->assertSame(null, $this->getJsonResponseContentValue(parent::$kernel->getContainer()
                ->getParameter('gesdinet_jwt_refresh_token.token_parameter_name')));
        }
    }

    /**
     * @return void
     */
    public function testAddRefreshTokenToJWTRefreshRequest(): void
    {
        $this->runCommand('doctrine:fixtures:load --append --group=UserFixtures');
        $this->output->writeln("\r\n<info>Test the token refresh:</info>");
        $this->client->catchExceptions(false);

        $this->simulateLogin('ROLE_ADMIN');

        if ($this->authorizationHeaderTypeTokenExtractorIsEnabled()) {
            $this->output->writeln("\n<info>Save the refresh token after login ...</info>");
            $refreshToken = $this->getJsonResponseContentValue(parent::$kernel->getContainer()->getParameter('gesdinet_jwt_refresh_token.token_parameter_name'));
        }

        $this->output->writeln("\n<info>Waiting for token expiration (sleep: 6 seconds -> (the token expiration time is 5 seconds in test environment.))</info>");
        sleep(6);

        if ($this->authorizationHeaderTypeTokenExtractorIsEnabled()) {
            $this->resfreshTokenInAuthorizationHeaderTypeTokenExtractorModeTest(
                $this->getJsonResponseContentValue('token'),
                (string)$refreshToken);
        } else {
            $this->resfreshTokenInSecureCookieTokenExtractorModeTest();
        }
    }

    /**
     * @param string $token
     * @param string $refreshToken
     * @return void
     */
    private function resfreshTokenInAuthorizationHeaderTypeTokenExtractorModeTest(string $token, string $refreshToken): void
    {
        $this->output->writeln("\n<info>Refresh the JWT token</info>");
        $refreshTokenParameterName = parent::$kernel->getContainer()
            ->getParameter('gesdinet_jwt_refresh_token.token_parameter_name');

        $this->output->writeln("<info>POST /token/refresh: Method Not Allowed (Allow: UPDATE)</info>");
        $exceptionThrown = false;
        try {
            $this->client->request('POST', '/token/refresh', [], [], [
                'CONTENT_TYPE' => 'application/json'
            ], json_encode([$refreshTokenParameterName => $refreshToken]));
        } catch (MethodNotAllowedHttpException $e) {
            $exceptionThrown = true;
        }
        $this->assertSame(true, $exceptionThrown);

        $this->client->request('UPDATE', '/token/refresh', [], [], [
            'CONTENT_TYPE' => 'application/json'
        ], json_encode([$refreshTokenParameterName => $refreshToken]));
        $this->assertSame(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
        $newToken = $this->getJsonResponseContentValue('token');
        $this->assertSame(true, !empty($newToken) && is_string($newToken));
        $this->assertSame(false, $token == $newToken);

        $this->output->writeln("\n<info>Invalid request with the old token ...</info>");
        $this->output->writeln("<info>Expected status code:401, with Expired JWT Token message (without AccessDeniedException!)</info>");
        $this->client->request('GET', '/authorization-tests/admin-role', [], [], $this->getAuthHeaders($token));
        $this->assertSame(Response::HTTP_UNAUTHORIZED, $this->client->getResponse()->getStatusCode());

        $this->output->writeln("\n<info>Valid request with the refreshed token</info>");
        $this->client->request('GET', '/authorization-tests/admin-role', [], [], $this->getAuthHeaders($newToken));
        $this->assertSame(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
    }

    /**
     * @return void
     */
    private function resfreshTokenInSecureCookieTokenExtractorModeTest(): void
    {
        $cookieName = parent::$kernel->getContainer()->getParameter('app.jwt_cookie_name');
        
        $this->output->writeln("\n<info>BEARER cookie expired ...</info>");
        $this->assertSame(true, empty($this->client->getCookieJar()->get($cookieName)));

        $this->output->writeln("<info>In secure mode expected: AccessDeniedException!</info>");
        $this->accessDeniedWithoutLoginTest('/authorization-tests/admin-role');

        $this->output->writeln("\n<info>Call the /token/refresh route and get a new BEARER cookie</info>");
        $this->output->writeln("\n<info>Only UPDATE Method Allowed on /token/refresh</info>");
        $this->methodNotAllowedOnRoute('GET', '/token/refresh');
        $this->methodNotAllowedOnRoute('POST', '/token/refresh');
        $this->methodNotAllowedOnRoute('PUT', '/token/refresh');
        $this->methodNotAllowedOnRoute('PATCH', '/token/refresh');
        
        $this->output->writeln("<info>Expected Status Code in secure mode 204 (HTTP_NO_CONTENT)</info>");
        $this->client->request('UPDATE', '/token/refresh');
        $this->assertSame(Response::HTTP_NO_CONTENT, $this->client->getResponse()->getStatusCode());
        $this->assertSame(false, empty($this->client->getCookieJar()->get($cookieName)));

        $this->output->writeln("\n<info>In secure mode the Refresh token need to be removed from the response content, immediately after the refresh!</info>");
        $refreshToken = $this->getJsonResponseContentValue(parent::$kernel->getContainer()->getParameter('gesdinet_jwt_refresh_token.token_parameter_name'));
        $this->assertSame(null, $refreshToken);

        $this->output->writeln("\n<info>Valid request with the new cookie</info>");
        $this->client->request('GET', '/authorization-tests/admin-role');
        $this->assertSame(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
    }
}