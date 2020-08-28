<?php

namespace App\Tests\Controller;

use App\Tests\AbstractSecurityTest;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

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
        $this->simulateLogin();

        $this->output->writeln("\n<info>Simulate a valid request with ROLE_USER ...</info>");
        if ($this->authorizationHeaderTypeTokenExtractorIsEnabled()) {
            $this->client->request('GET', '/authorization-tests/user-role', [], [], $this->getAuthHeaders());
        } else {
            $this->client->request('GET', '/authorization-tests/user-role');
        }

        $this->assertSame(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());

        $this->output->writeln("\n<info>Waiting for token expiration (sleep: 6 seconds -> (the token expiration time is 5 seconds in test environment.))</info>");
        sleep(6);
        $this->output->writeln("\n<info>Simulate an invalid request with the expired token: expected AccessDeniedException</info>");
        $this->expectException(AccessDeniedException::class);
        if ($this->authorizationHeaderTypeTokenExtractorIsEnabled()) {
            $this->client->request('GET', '/authorization-tests/user-role', [], [], $this->getAuthHeaders());
        } else {
            $this->client->request('GET', '/authorization-tests/user-role');
        }
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
        $this->accessDeniedForRoleTest('/authorization-tests/admin-role');
        $this->simulateLogin('ROLE_ADMIN');

        $this->output->writeln("\n<info>Simulate a valid request with ROLE_ADMIN ...</info>");
        if ($this->authorizationHeaderTypeTokenExtractorIsEnabled()) {
            $this->client->request('GET', '/authorization-tests/admin-role', [], [], $this->getAuthHeaders());
        } else {
            $this->client->request('GET', '/authorization-tests/admin-role');
        }

        $this->assertSame(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());

        $this->output->writeln("\n<info>Waiting for token expiration (sleep: 6 seconds -> (the token expiration time is 5 seconds in test environment.))</info>");
        sleep(6);
        $this->output->writeln("\n<info>Simulate an invalid request with the expired token: expected AccessDeniedException</info>");
        $this->expectException(AccessDeniedException::class);
        if ($this->authorizationHeaderTypeTokenExtractorIsEnabled()) {
            $this->client->request('GET', '/authorization-tests/admin-role', [], [], $this->getAuthHeaders());
        } else {
            $this->client->request('GET', '/authorization-tests/admin-role');
        }
    }
}