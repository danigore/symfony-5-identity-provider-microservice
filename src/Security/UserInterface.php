<?php

namespace App\Security;

use Lexik\Bundle\JWTAuthenticationBundle\Security\User\JWTUserInterface;

/**
 * Class UserInterface
 * @package App\Security
 */
interface UserInterface extends JWTUserInterface
{
    /**
     * @return int
     */
    public function getId(): int;
}