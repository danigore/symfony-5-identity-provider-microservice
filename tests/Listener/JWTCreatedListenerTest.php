<?php

namespace App\Tests\Listener;

use App\Tests\AbstractSecurityTest;

/**
 * Class JWTCreatedListenerTest
 * @package App\Tests\Listener
 */
class JWTCreatedListenerTest extends AbstractSecurityTest
{
    /**
     * @return void
     */
    public function testJWTPayloadExtendedWithTheUserId(): void
    {
        $this->runCommand('doctrine:fixtures:load --append --group=UserFixtures');
        $this->output->writeln("\r\n<info>Test the JWT payload included the user ID:</info>");

        // gets the special container that allows fetching private services
        $tokenDecoder = parent::$container->get('lexik_jwt_authentication.encoder.lcobucci');

        $this->simulateLogin('ROLE_ADMIN');
        $token = $this->getToken();
        $this->assertSame(true, !empty($token) && is_string($token));

        $this->output->writeln("\n<info>Decode the token</info>");
        $payload = $tokenDecoder->decode($token);
        $this->assertSame('dextermorgan@cvlt.dev', $payload['username']);
        $this->assertSame(true, in_array('ROLE_ADMIN', $payload['roles']));
        $this->assertSame(true, in_array('ROLE_USER', $payload['roles']));
        $this->assertSame(true, empty($payload['password']));
        $this->assertSame(1, $payload['id']);

        $this->output->writeln("\n<info>Waiting for token expiration (sleep: 6 seconds -> (the token expiration time is 5 seconds in test environment.))</info>");
        sleep(6);
        $this->refreshTheToken();
        $token = $this->getToken();

        $this->output->writeln("\n<info>Decode the token again</info>");
        $payload = $tokenDecoder->decode($token);
        $this->assertSame(1, $payload['id']);
    }
}