<?php

namespace App\DataFixtures;

use App\Entity\User;
use Doctrine\Bundle\FixturesBundle\FixtureGroupInterface;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\Common\Persistence\ObjectManager;
use Symfony\Component\Console\Output\ConsoleOutput;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;

/**
 * Class UserFixtures
 * @package App\DataFixtures
 */
class UserFixtures extends Fixture implements FixtureGroupInterface
{
    private const PAY_LOADS = [
        [
            'id' => 1,
            'email' => 'dextermorgan@cvlt.dev',
            'role' => 'ROLE_ADMIN',
            'password' => 'Debra',
        ],
        [
            'id' => 2,
            'email' => 'eleven@cvlt.dev',
            'role' => 'ROLE_USER',
            'password' => 'Eggo',
        ],
    ];

    private UserPasswordEncoderInterface $passwordEncoder;

    /**
     * UserFixtures constructor.
     * @param UserPasswordEncoderInterface $passwordEncoder
     */
    public function __construct(UserPasswordEncoderInterface $passwordEncoder)
    {
        $this->passwordEncoder = $passwordEncoder;
    }

    /**
     * @return array
     */
    public static function getGroups(): array
    {
        return ['UserFixtures'];
    }

    /**
     * @param ObjectManager $entityManager
     * @return void
     */
    public function load(ObjectManager $entityManager)
    {
        $output = new ConsoleOutput();

        $output->writeln("\r\n<info>Load Users</info>");

        $entityManager->clear();

        foreach (self::PAY_LOADS as $payLoad) {
            $user = new User();
            $user->setEmail($payLoad['email'])->setRoles([$payLoad['role']]);
            $user->setPassword($this->passwordEncoder->encodePassword($user, $payLoad['password']));

            $entityManager->persist($user);

            $output->writeln('<info>New User persisted with email: ' . $user->getEmail() . '</info>');

            unset($user);
        }

        $entityManager->flush();
    }
}