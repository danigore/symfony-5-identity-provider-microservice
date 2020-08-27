<?php

namespace App\Security;

use Lexik\Bundle\JWTAuthenticationBundle\Security\User\JWTUser;

/**
 * Class User
 * @package App\Security
 */
final class User extends JWTUser implements UserInterface
{
    /**
     * @var int $id
     */
    private int $id;

    /**
     * User constructor.
     * @param int $id
     * @param string $username
     * @param array $roles
     */
    public function __construct(int $id, string $username, array $roles = [])
    {
        parent::__construct($username, $roles);
        $this->id = $id;
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromPayload($username, array $payload)
    {
        if (isset($payload['roles'])) {
            return new self((int)$payload['id'], (string)$username, (array)$payload['roles']);
        }

        return new self((int)$payload['id'], (string)$username);
    }

    /**
     * @return int
     */
    public function getId(): int
    {
        return $this->id;
    }
}