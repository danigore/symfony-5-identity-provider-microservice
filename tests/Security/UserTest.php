<?php

namespace App\Tests\Security;

use App\Tests\AbstractSecurityTest;
use Symfony\Component\Security\Core\User\UserInterface;

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
        $this->assertEquals(true, $user instanceof UserInterface);
        $this->assertEquals('dextermorgan@cvlt.dev', $user->getUsername());
        $this->assertEquals(2, count($user->getRoles()));
        $this->assertEquals(1, $user->getId());

        $this->output->writeln("\r\n<info>Wait for token expiration ...</info>");
        sleep(6);
        $this->assertEquals(null, $this->getUser());

        $this->output->writeln("\r\n<info>Check again after a token refresh ...</info>");
        $this->refreshTheToken();

        $user = $this->getUser();
        $this->assertEquals(true, $user instanceof UserInterface);
        $this->assertEquals('dextermorgan@cvlt.dev', $user->getUsername());
        $this->assertEquals(2, count($user->getRoles()));
        $this->assertEquals(1, $user->getId());
    }
}