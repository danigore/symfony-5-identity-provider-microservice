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
        $this->assertEquals(true, !empty($token) && is_string($token));

        $this->output->writeln("\n<info>Decode the token</info>");
        $payload = $tokenDecoder->decode($token);
        $this->assertEquals('dextermorgan@cvlt.dev', $payload['username']);
        $this->assertEquals(true, in_array('ROLE_ADMIN', $payload['roles']));
        $this->assertEquals(true, in_array('ROLE_USER', $payload['roles']));
        $this->assertEquals(true, empty($payload['password']));
        $this->assertEquals(1, $payload['id']);
    }
}