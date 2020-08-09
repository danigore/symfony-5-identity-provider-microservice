<?php

namespace App\Listener;

use App\Service\DependencyInjection\JWTCookieExtractorDependencyInjectionService;
use Lexik\Bundle\JWTAuthenticationBundle\Event\AuthenticationSuccessEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Cookie;

/**
 * Class TokenRefreshListener
 * @package App\Listener
 */
class TokenRefreshListener implements EventSubscriberInterface
{
    /**
     * @var JWTCookieExtractorDependencyInjectionService $service
     */
    private JWTCookieExtractorDependencyInjectionService $service;

    /**
     * TokenRefreshListener constructor.
     *
     * @param JWTCookieExtractorDependencyInjectionService $service
     */
    public function __construct(JWTCookieExtractorDependencyInjectionService $service)
    {
        $this->service = $service;
    }

    /**
     * @param AuthenticationSuccessEvent $event
     * @return void
     */
    public function setRefreshToken(AuthenticationSuccessEvent $event)
    {
        if ($this->service->isAuthorizationHeaderExtractorEnabled()) {
            return;
        }

        $data = $event->getData();

        if (empty($data[$this->service->getRefreshTokenParameterName()])) {
            return;
        }

        $event->getResponse()->headers->setCookie(new Cookie(
            $this->service->getRefreshCookieName(),
            $data[$this->service->getRefreshTokenParameterName()],
            $this->service->getDateTimeByRefreshTokenTtl()));

        // remove the refresh_token from the response data
        unset($data[$this->service->getRefreshTokenParameterName()]);
        $event->setData($data);
    }

    /**
     * @return array
     */
    public static function getSubscribedEvents(): array
    {
        return ['lexik_jwt_authentication.on_authentication_success' => [['setRefreshToken']]];
    }
}