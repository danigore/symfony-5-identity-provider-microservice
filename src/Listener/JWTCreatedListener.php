<?php

namespace App\Listener;

use Lexik\Bundle\JWTAuthenticationBundle\Event\JWTCreatedEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Class JWTCreatedListener
 * @package App\Listener
 */
class JWTCreatedListener implements EventSubscriberInterface
{
    /**
     * @param JWTCreatedEvent $event
     * @return void
     */
    public function onJWTCreated(JWTCreatedEvent $event): void
    {
        // Careful: Before you add your own custom data, know that the JWT payload is not encrypted,
        // it is only base64 encoded. The token signature ensures its integrity (meaning it cannot be modified),
        // but anyone can read its content (try it using a simple tool like http://jwt.io/).
        $user = $event->getUser();

        if (!method_exists($user, 'getId')) {
            return;
        }

        $payload = $event->getData();
        $payload['id'] = $user->getId();

        $event->setData($payload);
    }

    /**
     * @return array
     */
    public static function getSubscribedEvents(): array
    {
        return [
            'lexik_jwt_authentication.on_jwt_created' => [['onJWTCreated']],
        ];
    }
}