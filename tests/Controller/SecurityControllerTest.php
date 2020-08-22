<?php

namespace App\Tests\Controller;

use App\Exception\LogoutNotSupportedWithAuthorizationHeaderTypeTokenExtractorException;
use App\Tests\AbstractSecurityTest;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException;

/**
 * Class SecurityControllerTest
 * @package App\Tests\Controller
 */
class SecurityControllerTest extends AbstractSecurityTest
{
    /**
     * @return void
     * @throws \Exception
     */
    public function testLogout()
    {
        $this->runCommand('doctrine:fixtures:load --append --group=UserFixtures');
        $this->output->writeln("\r\n<info>Test the logout route:</info>");
        $this->client->catchExceptions(false);

        $this->accessDeniedWithoutLoginTest('/logout', 'DELETE');

        $this->simulateLogin();

        if ($this->authorizationHeaderTypeTokenExtractorIsEnabled()) {
            return $this->logoutWithAuthorizationHeaderTypeTokenExtractorTest();
        }

        $this->logoutWithSecureCookieTokenExtractorTest(); 
    }

    /**
     * @return void
     */
    private function logoutWithAuthorizationHeaderTypeTokenExtractorTest(): void
    {
        $this->output->writeln("\n<error>Backend logout not supported with authorization header type token extractor!</error>");
        $this->output->writeln("<info>Expected exception on logout: LogoutNotSupportedWithAuthorizationHeaderTypeTokenExtractorException</info>");

        $exceptionThrown = false;
        try {
            $this->client->request('DELETE', '/logout', [], [], parent::getAuthHeaders(
                $this->getJsonResponseContentValue('token')));
        } catch (LogoutNotSupportedWithAuthorizationHeaderTypeTokenExtractorException $e) {
            $exceptionThrown = true;
        }
        $this->assertEquals(true, $exceptionThrown);
    }

    /**
     * @return void
     */
    private function logoutWithSecureCookieTokenExtractorTest(): void
    {
        $this->output->writeln("\n<info>Only DELETE Method Allowed on /logout</info>");
        $this->methodNotAllowedOnRoute('GET', '/logout');
        $this->methodNotAllowedOnRoute('POST', '/logout');
        $this->methodNotAllowedOnRoute('PUT', '/logout');
        $this->methodNotAllowedOnRoute('PATCH', '/logout');

        $this->client->request('DELETE', '/logout');
        $this->output->writeln("\n<info>Logout requested ...</info>");
        $this->assertEquals(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());

        $this->output->writeln("\n<info>After a logout request, a token refresh request should be denied! (Expected status code:401 (UNAUTHORIZED))</info>");
        $this->client->request('UPDATE', '/token/refresh');
        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $this->client->getResponse()->getStatusCode());
        
        $this->output->writeln("\n<info>Expected exception on authorized route: AccessDeniedException</info>");
        $this->accessDeniedWithoutLoginTest('/authorization-tests/user-role');
    }

    /**
     * @return void
     */
    public function testLoginCheck()
    {
        $this->runCommand('doctrine:fixtures:load --append --group=UserFixtures');
        $this->output->writeln("\r\n<info>Test the login route:</info>");
        $this->client->catchExceptions(false);

        $this->output->writeln("\n<info>Only POST Method Allowed on /login_check</info>");
        $this->methodNotAllowedOnLoginCheckTest('GET');
        $this->methodNotAllowedOnLoginCheckTest('PUT');
        $this->methodNotAllowedOnLoginCheckTest('DELETE');

        $this->output->writeln("\n<info>Simulate a login with ROLE_USER ...</info>");
        $this->simulateLogin();

        if ($this->authorizationHeaderTypeTokenExtractorIsEnabled()) {
            return $this->checkTokensTest();
        }
        
        $this->checkCookieTest();
    }

    /**
     * @param string $method
     * @return void
     */
    private function methodNotAllowedOnLoginCheckTest(string $method): void
    {
        $exceptionThrown = false;
        try {
            $this->client->request($method, '/login_check', [], [], [
                'CONTENT_TYPE' => 'application/json'
            ], json_encode(['username' => 'eleven@cvlt.dev', 'password' => 'Eggo']));
        } catch (MethodNotAllowedHttpException $e) {
            $exceptionThrown = true;
        }
        $this->assertEquals(true, $exceptionThrown);
    }

    /**
     * @return void
     */
    private function checkTokensTest(): void
    {
        $this->output->writeln("<error>lexik_jwt_authentication.token_extractors.authorization_header enabled</error>");
        $this->output->writeln("<error>This type of autentication is don't provide security against XSS attacks!</error>");
        $this->output->writeln("<error>more info: https://blog.liplex.de/improve-security-when-working-with-jwt-and-symfony/</error>");

        $token = $this->getJsonResponseContentValue('token');
        $this->assertEquals(true, !empty($token) && is_string($token));

        $this->output->writeln("\n<info>Save the refresh token ...</info>");
        $refreshToken = $this->getJsonResponseContentValue(parent::$kernel->getContainer()
            ->getParameter('gesdinet_jwt_refresh_token.token_parameter_name'));
        $this->assertEquals(true, !empty($refreshToken) && is_string($refreshToken));
    }

    /**
     * @return void
     */
    private function checkCookieTest(): void
    {
        $this->output->writeln("<info>Secure httponly cookie token extractor is enabled ... Great!</info>");
        $this->assertEquals(true, $this->client->getCookieJar()->get(parent::$kernel->getContainer()
            ->getParameter('app.jwt_cookie_name'))->isHttpOnly());

        $this->output->writeln("\n<info>In secure mode the Refresh token need to be removed from the response content, immediately after the login!</info>");
        $this->assertEquals(null, $this->getJsonResponseContentValue(parent::$kernel->getContainer()
            ->getParameter('gesdinet_jwt_refresh_token.token_parameter_name')));
    }

    /**
     * @return void
     */
    public function testTokenRefresh(): void
    {
        $this->runCommand('doctrine:fixtures:load --append --group=UserFixtures');
        $this->output->writeln("\r\n<info>Test the token refresh:</info>");
        $this->client->catchExceptions(false);

        $this->output->writeln("\n<info>Simulate a valid request with ROLE_ADMIN ...</info>");
        $this->simulateLogin('ROLE_ADMIN');

        if ($this->authorizationHeaderTypeTokenExtractorIsEnabled()) {
            $this->output->writeln("\n<info>Save the refresh token after login ...</info>");
            $refreshToken = $this->getJsonResponseContentValue(parent::$kernel->getContainer()->getParameter('gesdinet_jwt_refresh_token.token_parameter_name'));
            $this->assertEquals(true, !empty($refreshToken) && is_string($refreshToken));
        } else {
            $this->assertEquals(null, $this->getJsonResponseContentValue(parent::$kernel->getContainer()
                ->getParameter('gesdinet_jwt_refresh_token.token_parameter_name')));

            $this->client->request('GET', '/authorization-tests/admin-role');

            $this->output->writeln("\n<info>... Check again the refresh token is removed, after a valid request on an authorized route ...</info>");
            $this->assertEquals(null, $this->getJsonResponseContentValue(parent::$kernel->getContainer()
                ->getParameter('gesdinet_jwt_refresh_token.token_parameter_name')));
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
        $this->assertEquals(true, $exceptionThrown);

        $this->client->request('UPDATE', '/token/refresh', [], [], [
            'CONTENT_TYPE' => 'application/json'
        ], json_encode([$refreshTokenParameterName => $refreshToken]));
        $this->assertEquals(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
        $newToken = $this->getJsonResponseContentValue('token');
        $this->assertEquals(true, !empty($newToken) && is_string($newToken));
        $this->assertEquals(false, $token == $newToken);

        $this->output->writeln("\n<info>Invalid request with the old token ...</info>");
        $this->output->writeln("<info>Expected status code:401, with Expired JWT Token message (without AccessDeniedException!)</info>");
        $this->client->request('GET', '/authorization-tests/admin-role', [], [], $this->getAuthHeaders($token));
        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $this->client->getResponse()->getStatusCode());

        $this->output->writeln("\n<info>Valid request with the refreshed token</info>");
        $this->client->request('GET', '/authorization-tests/admin-role', [], [], $this->getAuthHeaders($newToken));
        $this->assertEquals(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
    }

    /**
     * @return void
     */
    private function resfreshTokenInSecureCookieTokenExtractorModeTest(): void
    {
        $cookieName = parent::$kernel->getContainer()->getParameter('app.jwt_cookie_name');
        
        $this->output->writeln("\n<info>BEARER cookie expired ...</info>");
        $this->assertEquals(true, empty($this->client->getCookieJar()->get($cookieName)));

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
        $this->assertEquals(Response::HTTP_NO_CONTENT, $this->client->getResponse()->getStatusCode());
        $this->assertEquals(false, empty($this->client->getCookieJar()->get($cookieName)));

        $this->output->writeln("\n<info>In secure mode the Refresh token need to be removed from the response content, immediately after the refresh!</info>");
        $refreshToken = $this->getJsonResponseContentValue(parent::$kernel->getContainer()->getParameter('gesdinet_jwt_refresh_token.token_parameter_name'));
        $this->assertEquals(null, $refreshToken);

        $this->output->writeln("\n<info>Valid request with the new cookie</info>");
        $this->client->request('GET', '/authorization-tests/admin-role');
        $this->assertEquals(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
    }
}