<?php

namespace App\Subscriber;

use Lexik\Bundle\JWTAuthenticationBundle\Event\AuthenticationSuccessEvent;
use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Class TokenStorageCleanerSubscriber
 * @package App\Subscriber
 */
class TokenStorageCleanerSubscriber implements EventSubscriberInterface
{
    /**
     * @var Container $container
     */
    private Container $container;

    /**
     * TokenStorageCleanerSubscriber constructor.
     *
     * @param Container $container
     */
    public function __construct(Container $container)
    {
        $this->container = $container;
    }

    /**
     * @param AuthenticationSuccessEvent $event
     * @return void
     */
    public function cleanTokenStorage(AuthenticationSuccessEvent $event): void
    {
        if ($this->container->has('security.token_storage')) {
            $this->container->get('security.token_storage')->setToken(null);
        }
    }

    /**
     * @return array
     */
    public static function getSubscribedEvents(): array
    {
        return [
            'lexik_jwt_authentication.on_authentication_success' => [['cleanTokenStorage']],
        ];
    }
}