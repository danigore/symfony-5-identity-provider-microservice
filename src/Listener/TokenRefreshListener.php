<?php

namespace App\Listener;

use App\Service\DependencyInjection\JWTCookieExtractorDependencyInjectionService;
use Lexik\Bundle\JWTAuthenticationBundle\Event\AuthenticationSuccessEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

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
    public function onAuthenticationSuccess(AuthenticationSuccessEvent $event): void
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
     * @param RequestEvent $event
     * @return void
     */
    public function onJWTRefreshRequest(RequestEvent $event): void
    {
        $request = $event->getRequest();

        // https://symfony.com/doc/2.6//cookbook/service_container/event_listener.html#request-events-checking-types
        // A single page can make several requests (one master request, and then multiple sub-requests) ...
        if (!$event->isMasterRequest()
            || !'gesdinet_jwt_refresh_token' === $request->attributes->get('_route')
            || !$request->cookies->has($this->service->getRefreshCookieName())) {
            return;
        }

        $request->attributes->set($this->service->getRefreshTokenParameterName(),
            $request->cookies->get($this->service->getRefreshCookieName()));
    }

    /**
     * @return array
     */
    public static function getSubscribedEvents(): array
    {
        return [
            'lexik_jwt_authentication.on_authentication_success' => [['onAuthenticationSuccess']],
            KernelEvents::REQUEST => [['onJWTRefreshRequest']],
        ];
    }
}