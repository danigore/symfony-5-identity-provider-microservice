<?php

namespace App\Tests\Security;

use App\Security\UserInterface;
use App\Tests\AbstractSecurityTest;

/**
 * Class UserTest
 * @package App\Tests\Security
 */
class UserTest extends AbstractSecurityTest
{
    /**
     * @return void
     * @throws \Exception
     */
    public function testExpectedAuthenticatedUserObjectProperties(): void
    {
        $this->runCommand('doctrine:fixtures:load --append --group=UserFixtures');
        $this->output->writeln("\r\n<info>Test the properties of a logged in User</info>");
        $this->client->catchExceptions(false);

        $this->simulateLogin('ROLE_ADMIN');

        $user = $this->getUser();
        $this->assertSame(true, $user instanceof UserInterface);
        $this->assertSame('dextermorgan@cvlt.dev', $user->getUsername());
        $this->assertSame(2, count($user->getRoles()));
        $this->assertSame(1, $user->getId());

        $this->output->writeln("\r\n<info>Wait for token expiration ...</info>");
        sleep(6);
        $this->assertSame(null, $this->getUser());

        $this->output->writeln("\r\n<info>Check again after a token refresh ...</info>");
        $this->refreshTheToken();

        $user = $this->getUser();
        $this->assertSame(true, $user instanceof UserInterface);
        $this->assertSame('dextermorgan@cvlt.dev', $user->getUsername());
        $this->assertSame(2, count($user->getRoles()));
        $this->assertSame(1, $user->getId());
    }
}