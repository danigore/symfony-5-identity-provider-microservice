<?php

namespace App\Tests\Controller;

use Symfony\Component\Console\Output\ConsoleOutput;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

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
        $output = new ConsoleOutput();

        $this->runCommand('doctrine:fixtures:load --append --group=UserFixtures');
        $output->writeln("\r\n<info>Test a route where user role (ROLE_USER) is required:</info>");
        $this->client->catchExceptions(false);

        // Valid request without JWT token
        $output->writeln("<info>Valid request without JWT token ...</info>");
        $exceptionThrown = false;
        try {
            $this->client->request('GET', '/authorization-tests/user-role');
        } catch (AccessDeniedException $e) {
            $exceptionThrown = true;
        }
        $this->assertEquals(true, $exceptionThrown);

        // Valid request with ROLE_USER
        $output->writeln("\n<info>Valid request with ROLE_USER ...</info>");
        $this->client->request('POST', '/login_check', [], [], [
            'CONTENT_TYPE' => 'application/json'
        ], json_encode(['username' => 'eleven@cvlt.dev', 'password' => 'Eggo']));

        if (!$token = $this->getToken()) {
            // secure httponly cookie enabled, there is no need set any authorization header
            $output->writeln("<info>Secure httponly cookie token extractor is enabled ... Great!</info>");
            $this->client->request('GET', '/authorization-tests/user-role');
            $this->assertEquals(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
        } else {
            // lexik_jwt_authentication.token_extractors.authorization_header enabled
            // This type of autentication is don't provide security against XSS attacks!
            // more info: https://blog.liplex.de/improve-security-when-working-with-jwt-and-symfony/
            $output->writeln("<error>lexik_jwt_authentication.token_extractors.authorization_header enabled</error>");
            $output->writeln("<error>This type of autentication is don't provide security against XSS attacks!</error>");
            $output->writeln("<error>more info: https://blog.liplex.de/improve-security-when-working-with-jwt-and-symfony/</error>");
            $this->client->request('GET', '/authorization-tests/user-role', [], [], parent::getAuthHeaders($token));
            $this->assertEquals(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
        }
    }

    /**
     * @return void
     * @throws \Exception
     */
    public function testAdminRoleRequired()
    {
        $output = new ConsoleOutput();

        $this->runCommand('doctrine:fixtures:load --append --group=UserFixtures');
        $output->writeln("\r\n<info>Test a route where admin role (ROLE_ADMIN) is required:</info>");
        $this->client->catchExceptions(false);

        // Valid request without JWT token
        $output->writeln("<info>Valid request without JWT token ...</info>");
        $exceptionThrown = false;
        try {
            $this->client->request('GET', '/authorization-tests/admin-role');
        } catch (AccessDeniedException $e) {
            $exceptionThrown = true;
        }
        $this->assertEquals(true, $exceptionThrown);

        // Valid request with ROLE_USER
        $output->writeln("\n<info>Valid request with ROLE_USER ...</info>");
        $this->client->request('POST', '/login_check', [], [], [
            'CONTENT_TYPE' => 'application/json'
        ], json_encode(['username' => 'eleven@cvlt.dev', 'password' => 'Eggo']));

        $exceptionThrown = false;
        try {
            if (!$token = $this->getToken()) {
                $output->writeln("<info>Secure httponly cookie token extractor is enabled ... Great!</info>");
                $this->client->request('GET', '/authorization-tests/admin-role');
                $this->assertEquals(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
            } else {
                $output->writeln("<error>lexik_jwt_authentication.token_extractors.authorization_header enabled</error>");
                $output->writeln("<error>This type of autentication is don't provide security against XSS attacks!</error>");
                $output->writeln("<error>more info: https://blog.liplex.de/improve-security-when-working-with-jwt-and-symfony/</error>");
                $this->client->request('GET', '/authorization-tests/admin-role', [], [], parent::getAuthHeaders($token));
                $this->assertEquals(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
            }
        } catch (AccessDeniedException $e) {
            $exceptionThrown = true;
        }
        $this->assertEquals(true, $exceptionThrown);

        // Valid request with ROLE_ADMIN
        $output->writeln("\n<info>Valid request with ROLE_ADMIN ...</info>");
        $this->client->request('POST', '/login_check', [], [], [
            'CONTENT_TYPE' => 'application/json'
        ], json_encode(['username' => 'dextermorgan@cvlt.dev', 'password' => 'Debra']));

        if (!$token = $this->getToken()) {
            $output->writeln("<info>Secure httponly cookie token extractor is enabled ... Great!</info>");
            $this->client->request('GET', '/authorization-tests/admin-role');
            $this->assertEquals(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
        } else {
            $output->writeln("<error>lexik_jwt_authentication.token_extractors.authorization_header enabled</error>");
            $output->writeln("<error>This type of autentication is don't provide security against XSS attacks!</error>");
            $output->writeln("<error>more info: https://blog.liplex.de/improve-security-when-working-with-jwt-and-symfony/</error>");
            $this->client->request('GET', '/authorization-tests/admin-role', [], [], parent::getAuthHeaders($token));
            $this->assertEquals(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
        }
    }
}