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
        $output->writeln("<info>Valid request with ROLE_USER ...</info>");
        $this->client->request('POST', '/login_check', [], [], [
            'CONTENT_TYPE' => 'application/json'
        ], json_encode(['username' => 'eleven@cvlt.dev', 'password' => 'Eggo']));
        $token = json_decode($this->client->getResponse()->getContent(), true)["token"];
        $this->client->request('GET', '/authorization-tests/user-role', [], [], parent::getAuthHeaders($token));
        $response = $this->client->getResponse();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode());
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
        $output->writeln("<info>Valid request with ROLE_USER ...</info>");
        $this->client->request('POST', '/login_check', [], [], [
            'CONTENT_TYPE' => 'application/json'
        ], json_encode(['username' => 'eleven@cvlt.dev', 'password' => 'Eggo']));
        $token = json_decode($this->client->getResponse()->getContent(), true)["token"];

        $exceptionThrown = false;
        try {
            $this->client->request('GET', '/authorization-tests/admin-role', [], [], parent::getAuthHeaders($token));
        } catch (AccessDeniedException $e) {
            $exceptionThrown = true;
        }
        $this->assertEquals(true, $exceptionThrown);

        // Valid request with ROLE_ADMIN
        $output->writeln("<info>Valid request with ROLE_ADMIN ...</info>");
        $this->client->request('POST', '/login_check', [], [], [
            'CONTENT_TYPE' => 'application/json'
        ], json_encode(['username' => 'dextermorgan@cvlt.dev', 'password' => 'Debra']));
        $token = json_decode($this->client->getResponse()->getContent(), true)["token"];
        $this->client->request('GET', '/authorization-tests/admin-role', [], [], parent::getAuthHeaders($token));
        $response = $this->client->getResponse();
        $this->assertEquals(Response::HTTP_OK, $response->getStatusCode());
    }
}