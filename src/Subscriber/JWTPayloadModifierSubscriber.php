<?php

namespace App\Subscriber;

use App\Entity\User;
use Lexik\Bundle\JWTAuthenticationBundle\Event\JWTCreatedEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Class JWTPayloadModifierSubscriber
 * @package App\Subscriber
 */
class JWTPayloadModifierSubscriber implements EventSubscriberInterface
{
    /**
     * @param JWTCreatedEvent $event
     * @return void
     */
    public function modifyJWTPayload(JWTCreatedEvent $event): void
    {
        // Careful: Before you add your own custom data, know that the JWT payload is not encrypted,
        // it is only base64 encoded. The token signature ensures its integrity (meaning it cannot be modified),
        // but anyone can read its content (try it using a simple tool like http://jwt.io/).
        $user = $event->getUser();

        if (!$user instanceof User) {
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
            'lexik_jwt_authentication.on_jwt_created' => [['modifyJWTPayload']],
        ];
    }
}