<?php

namespace App\Tests\Controller;

use App\Tests\AbstractSecurityTest;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class AuthorizationTestRoutesControllerTest
 * @package App\Tests\Controller
 */
class AuthorizationTestRoutesControllerTest extends AbstractSecurityTest
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

        $this->accessDeniedWithoutLoginTest('/authorization-tests/user-role');

        $this->output->writeln("\n<info>Simulate a login with ROLE_USER ...</info>");
        $this->simulateLogin();

        if ($this->authorizationHeaderTypeTokenExtractorIsEnabled()) {
            $this->client->request('GET', '/authorization-tests/user-role', [], [], $this->getAuthHeaders());
        } else {
            $this->client->request('GET', '/authorization-tests/user-role');
        }

        $this->assertEquals(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
    }

    /**
     * @return void
     * @throws \Exception
     */
    public function testAdminRoleRequired()
    {
        $this->runCommand('doctrine:fixtures:load --append --group=UserFixtures');
        $this->output->writeln("\r\n<info>Test a route where admin role (ROLE_ADMIN) is required:</info>");
        $this->client->catchExceptions(false);

        $this->accessDeniedWithoutLoginTest('/authorization-tests/admin-role');

        $this->output->writeln("\n<info>Simulate an invalid request with ROLE_USER ...</info>");
        $this->accessDeniedForRoleTest('/authorization-tests/admin-role');

        $this->output->writeln("\n<info>Simulate a valid request with ROLE_ADMIN ...</info>");
        $this->simulateLogin('ROLE_ADMIN');

        if ($this->authorizationHeaderTypeTokenExtractorIsEnabled()) {
            $this->client->request('GET', '/authorization-tests/admin-role', [], [], $this->getAuthHeaders());
        } else {
            $this->client->request('GET', '/authorization-tests/admin-role');
        }

        $this->assertEquals(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
    }
}