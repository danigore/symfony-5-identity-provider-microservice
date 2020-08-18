<?php

namespace App\Tests\Controller;

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
     * @param string $method
     * @param string|null $role
     * @return void
     */
    protected function simulateLogin(string $method = 'POST', ?string $role = null): void
    {
        $this->client->request($method, '/login_check', [], [], [
            'CONTENT_TYPE' => 'application/json'
        ], json_encode($this->getUserCredentialsByRole($role)));
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