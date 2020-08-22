<?php

namespace App\Tests\Controller;

use Symfony\Component\Security\Core\Exception\AccessDeniedException;

/**
 * Class AbstractSecurityControllerTest
 * @package App\Tests\Controller
 */
abstract class AbstractSecurityControllerTest extends AbstractControllerTest
{
    /**
     * @return boolean
     */
    protected function authorizationHeaderTypeTokenExtractorIsEnabled(): bool
    {
        return !empty($this->getJsonResponseContentValue('token'));
    }

    /**
     * Simulate a login request by ROLE
     *
     * @param string|null $role
     * @return void
     */
    protected function simulateLogin(?string $role = null): void
    {
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
            $token = parent::getJsonResponseContentValue('token');
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
        $this->output->writeln("<info>Invalid request without JWT token ...</info>");
        $exceptionThrown = false;
        try {
            $this->client->request($method, $uri);
        } catch (AccessDeniedException $e) {
            $exceptionThrown = true;
        }
        $this->assertEquals(true, $exceptionThrown);
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
        $this->assertEquals(true, $exceptionThrown);
    }

    /**
     * @param string|null $role
     * @return array
     */
    private function getUserCredentialsByRole(?string $role): array
    {
        switch ($role) {
            case 'ROLE_ADMIN': return ['username' => 'dextermorgan@cvlt.dev', 'password' => 'Debra'];
            default: return ['username' => 'eleven@cvlt.dev', 'password' => 'Eggo'];
        }
    }
}