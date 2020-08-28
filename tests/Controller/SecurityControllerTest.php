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
        $this->assertSame(true, $exceptionThrown);
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
        $this->assertSame(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());

        $this->output->writeln("\n<info>After a logout request, a token refresh request should be denied! (Expected status code:401 (UNAUTHORIZED))</info>");
        $this->client->request('UPDATE', '/token/refresh');
        $this->assertSame(Response::HTTP_UNAUTHORIZED, $this->client->getResponse()->getStatusCode());
        
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
        $this->assertSame(true, $exceptionThrown);
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
        $this->assertSame(true, !empty($token) && is_string($token));

        $this->output->writeln("\n<info>Save the refresh token ...</info>");
        $refreshToken = $this->getJsonResponseContentValue(parent::$kernel->getContainer()
            ->getParameter('gesdinet_jwt_refresh_token.token_parameter_name'));
        $this->assertSame(true, !empty($refreshToken) && is_string($refreshToken));
    }

    /**
     * @return void
     */
    private function checkCookieTest(): void
    {
        $this->output->writeln("<info>Secure httponly cookie token extractor is enabled ... Great!</info>");
        $this->assertSame(true, $this->client->getCookieJar()->get(parent::$kernel->getContainer()
            ->getParameter('app.jwt_cookie_name'))->isHttpOnly());

        $this->output->writeln("\n<info>In secure mode the Refresh token need to be removed from the response content, immediately after the login!</info>");
        $this->assertSame(null, $this->getJsonResponseContentValue(parent::$kernel->getContainer()
            ->getParameter('gesdinet_jwt_refresh_token.token_parameter_name')));
    }
}