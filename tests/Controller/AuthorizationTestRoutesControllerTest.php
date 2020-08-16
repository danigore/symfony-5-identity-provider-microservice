<?php

namespace App\Tests\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * Class AuthorizationTestRoutesControllerTest
 * @package App\Tests\Controller
 */
class AuthorizationTestRoutesControllerTest extends AbstractControllerTest
{
    /**
     * @return void
     * @throws \Exception
     */
    public function testUserRoleRequired()
    {
        $this->runCommand('doctrine:fixtures:load --append --group=UserFixtures');
        $this->output->writeln("\r\n<info>Test a route where user role (ROLE_USER) is required:</info>");
        $this->client->catchExceptions(false);

        // Valid request without JWT token
        $this->output->writeln("<info>Invalid request without JWT token ...</info>");
        $exceptionThrown = false;
        try {
            $this->client->request('GET', '/authorization-tests/user-role');
        } catch (AccessDeniedException $e) {
            $exceptionThrown = true;
        }
        $this->assertEquals(true, $exceptionThrown);

        // Valid request with ROLE_USER
        $this->output->writeln("\n<info>Valid request with ROLE_USER ...</info>");
        $this->client->request('POST', '/login_check', [], [], [
            'CONTENT_TYPE' => 'application/json'
        ], json_encode(['username' => 'eleven@cvlt.dev', 'password' => 'Eggo']));

        if (!$token = $this->getJsonResponseContentValue('token')) {
            $this->output->writeln("<info>Secure httponly cookie token extractor is enabled ... Great!</info>");
            $this->client->request('GET', '/authorization-tests/user-role');
        } else {
            $this->output->writeln("<error>lexik_jwt_authentication.token_extractors.authorization_header enabled</error>");
            $this->output->writeln("<error>This type of autentication is don't provide security against XSS attacks!</error>");
            $this->output->writeln("<error>more info: https://blog.liplex.de/improve-security-when-working-with-jwt-and-symfony/</error>");
            $this->client->request('GET', '/authorization-tests/user-role', [], [], parent::getAuthHeaders($token));
        }
        $this->assertEquals(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
    }

    /**
     * @return void
     * @throws \Exception
     * @throws ParseException
     */
    public function testAdminRoleRequired()
    {
        $this->runCommand('doctrine:fixtures:load --append --group=UserFixtures');
        $lexikJwtConfig = Yaml::parseFile(parent::$kernel->getContainer()->getParameter('kernel.project_dir').'/config/packages/lexik_jwt_authentication.yaml');
        if (!empty($lexikJwtConfig['lexik_jwt_authentication']['token_extractors']['cookie']['name'])) {
            $cookieName = $lexikJwtConfig['lexik_jwt_authentication']['token_extractors']['cookie']['name'];
        } else {
            $cookieName = '';
        }
        $this->output->writeln("\r\n<info>Test a route where admin role (ROLE_ADMIN) is required:</info>");
        $this->client->catchExceptions(false);

        // Valid request without JWT token
        $this->output->writeln("<info>Invalid request without JWT token ...</info>");
        $exceptionThrown = false;
        try {
            $this->client->request('GET', '/authorization-tests/admin-role');
        } catch (AccessDeniedException $e) {
            $exceptionThrown = true;
        }
        $this->assertEquals(true, $exceptionThrown);

        // Valid request with ROLE_USER
        $this->output->writeln("\n<info>Invalid request with ROLE_USER ...</info>");
        $this->client->request('POST', '/login_check', [], [], [
            'CONTENT_TYPE' => 'application/json'
        ], json_encode(['username' => 'eleven@cvlt.dev', 'password' => 'Eggo']));

        $exceptionThrown = false;
        try {
            if (!$token = $this->getJsonResponseContentValue('token')) {
                $this->client->request('GET', '/authorization-tests/admin-role');
            } else {
                $this->client->request('GET', '/authorization-tests/admin-role', [], [], parent::getAuthHeaders($token));
            }
        } catch (AccessDeniedException $e) {
            $exceptionThrown = true;
        }
        $this->assertEquals(true, $exceptionThrown);

        // Valid request with ROLE_ADMIN
        $this->output->writeln("\n<info>Valid request with ROLE_ADMIN ...</info>");
        $this->client->request('POST', '/login_check', [], [], [
            'CONTENT_TYPE' => 'application/json'
        ], json_encode(['username' => 'dextermorgan@cvlt.dev', 'password' => 'Debra']));

        if (!$token = $this->getJsonResponseContentValue('token')) {
            $this->output->writeln("<info>Secure httponly cookie token extractor is enabled ... Great!</info>");
            $this->assertEquals(true, $this->client->getCookieJar()->get($cookieName)->isHttpOnly());
            $this->output->writeln("\n<info>In secure mode the Refresh token need to be removed from the response content, immediately after the login!</info>");
            $refreshToken = $this->getJsonResponseContentValue(parent::$kernel->getContainer()->getParameter('gesdinet_jwt_refresh_token.token_parameter_name'));
            $this->assertEquals(null, $refreshToken);

            $this->client->request('GET', '/authorization-tests/admin-role');

            $this->output->writeln("<info>... Check again the refresh token is removed, after a valid request on an authorized route ...</info>");
            $refreshToken = $this->getJsonResponseContentValue(parent::$kernel->getContainer()->getParameter('gesdinet_jwt_refresh_token.token_parameter_name'));
            $this->assertEquals(null, $refreshToken);
        } else {
            $this->output->writeln("<error>lexik_jwt_authentication.token_extractors.authorization_header enabled</error>");
            $this->output->writeln("<error>This type of autentication is don't provide security against XSS attacks!</error>");
            $this->output->writeln("<error>more info: https://blog.liplex.de/improve-security-when-working-with-jwt-and-symfony/</error>");
            
            // Save the refresh token
            $this->output->writeln("\n<info>Save the refresh token ...</info>");
            $refreshToken = $this->getJsonResponseContentValue(parent::$kernel->getContainer()->getParameter('gesdinet_jwt_refresh_token.token_parameter_name'));
            $this->assertEquals(true, !empty($refreshToken) && is_string($refreshToken));
            
            $this->client->request('GET', '/authorization-tests/admin-role', [], [], parent::getAuthHeaders($token));
        }
        $this->assertEquals(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());

        $this->output->writeln("\n<info>Waiting for token expiration (sleep: 6 seconds -> (the token expiration time is 5 seconds in test environment.))</info>");
        sleep(6);

        // Refresh the token
        if (!$token) {
            $this->output->writeln("\n<info>BEARER cookie expired ...</info>");
            $this->assertEquals(true, empty($this->client->getCookieJar()->get($cookieName)));
            $this->output->writeln("<info>In secure mode expected: AccessDeniedException!</info>");
            $exceptionThrown = false;
            try {
                $this->client->request('GET', '/authorization-tests/admin-role');
            } catch (AccessDeniedException $e) {
                $exceptionThrown = true;
            }
            $this->assertEquals(true, $exceptionThrown);

            $this->output->writeln("\n<info>Call the /token/refresh route and get a new BEARER cookie</info>");
            $this->output->writeln("<info>Expected Status Code in secure mode 204 (HTTP_NO_CONTENT)</info>");
            $this->client->request('POST', '/token/refresh');
            $this->assertEquals(Response::HTTP_NO_CONTENT, $this->client->getResponse()->getStatusCode());
            $this->assertEquals(false, empty($this->client->getCookieJar()->get($cookieName)));

            $this->output->writeln("\n<info>In secure mode the Refresh token need to be removed from the response content, immediately after the refresh!</info>");
            $refreshToken = $this->getJsonResponseContentValue(parent::$kernel->getContainer()->getParameter('gesdinet_jwt_refresh_token.token_parameter_name'));
            $this->assertEquals(null, $refreshToken);

            $this->output->writeln("\n<info>Valid request with the new cookie</info>");
            $this->client->request('GET', '/authorization-tests/admin-role');
            $this->assertEquals(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
        } else {
            $this->output->writeln("\n<info>Refresh the JWT token</info>");
            $this->client->request('POST', '/token/refresh', [], [], [
                'CONTENT_TYPE' => 'application/json'
            ], json_encode([parent::$kernel->getContainer()->getParameter('gesdinet_jwt_refresh_token.token_parameter_name') => $refreshToken]));
            $this->assertEquals(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());

            $newToken = $this->getJsonResponseContentValue('token');
            $this->assertEquals(true, !empty($newToken) && is_string($newToken));
            $this->assertEquals(false, $token == $newToken);

            $this->output->writeln("\n<info>Invalid request with the old token ...</info>");
            $this->output->writeln("<info>Expected status code:401, with Expired JWT Token message (without AccessDeniedException!)</info>");
            $this->client->request('GET', '/authorization-tests/admin-role', [], [], parent::getAuthHeaders($token));
            $this->assertEquals(Response::HTTP_UNAUTHORIZED, $this->client->getResponse()->getStatusCode());

            $this->output->writeln("\n<info>Valid request with the refreshed token</info>");
            $this->client->request('GET', '/authorization-tests/admin-role', [], [], parent::getAuthHeaders($newToken));
            $this->assertEquals(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
        }
    }
}