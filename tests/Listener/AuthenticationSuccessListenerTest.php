<?php

namespace App\Tests\Listener;

use App\Tests\AbstractSecurityTest;

/**
 * Class AuthenticationSuccessListenerTest
 * @package App\Tests\Listener
 */
class AuthenticationSuccessListenerTest extends AbstractSecurityTest
{
    /**
     * Across the security.token_storage, originally you can get a UsernamePasswordToken object,
     * (what is not related with the lexikJWT), and from that the original User ENTITY accessable
     * immediately after the login.
     * Even worst than, the entity still available through this service, after the JWT expiration too!
     *
     * @return void
     */
    public function testTokenStorageCleanedAfterAuthenticationAndTokenRefresh(): void
    {
        $this->runCommand('doctrine:fixtures:load --append --group=UserFixtures');
        $this->output->writeln("\r\n<info>Test there is no token in the security.token_storage</info>");
        $this->client->catchExceptions(false);

        $this->simulateLogin('ROLE_ADMIN');
        $this->assertSame(null, parent::$container->get('security.token_storage')->getToken());

        $this->output->writeln("\r\n<info>Check again after a token refresh ...</info>");
        $this->refreshTheToken();
        $this->assertSame(null, parent::$container->get('security.token_storage')->getToken());
    }
}