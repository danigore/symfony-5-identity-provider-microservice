<?php

namespace App\Subscriber;

use App\Service\JWTConfigurationService;
use Lexik\Bundle\JWTAuthenticationBundle\Event\AuthenticationSuccessEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Class TokenRefresherSubscriber
 * @package App\Subscriber
 */
class TokenRefresherSubscriber implements EventSubscriberInterface
{
    /**
     * @var JWTConfigurationService $service
     */
    private JWTConfigurationService $service;

    /**
     * TokenRefresherSubscriber constructor.
     *
     * @param JWTConfigurationService $service
     */
    public function __construct(JWTConfigurationService $service)
    {
        $this->service = $service;
    }

    /**
     * Set the refresh token cookie if the cookie token extractor mode is enabled.
     * 
     * @param AuthenticationSuccessEvent $event
     * @return void
     */
    public function setRefreshTokenCookie(AuthenticationSuccessEvent $event): void
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
    }

    /**
     * Remove the refresh_token from the response data
     * 
     * @param AuthenticationSuccessEvent $event
     * @return void
     */
    public function removeRefreshTokenFromResponse(AuthenticationSuccessEvent $event): void
    {
        if ($this->service->isAuthorizationHeaderExtractorEnabled()) {
            return;
        }

        $data = $event->getData();

        if (empty($data[$this->service->getRefreshTokenParameterName()])) {
            return;
        }

        unset($data[$this->service->getRefreshTokenParameterName()]);
        $event->setData($data);
    }

    /**
     * Add the refresh token to the request, if the requested route is the gesdinet_jwt_refresh_token
     * 
     * @param RequestEvent $event
     * @return void
     */
    public function addRefreshTokenToJWTRefreshRequest(RequestEvent $event): void
    {
        $request = $event->getRequest();
        // https://symfony.com/doc/2.6//cookbook/service_container/event_listener.html#request-events-checking-types
        // A single page can make several requests (one master request, and then multiple sub-requests) ...
        if (!$event->isMasterRequest()
            || !('gesdinet_jwt_refresh_token' === $request->get('_route'))
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
            'lexik_jwt_authentication.on_authentication_success' => [
                // priority, which is a positive or negative integer that defaults to 0
                // and it controls the order in which listeners are executed
                // (the higher the number, the earlier a listener is executed).
                // This is useful when you need to guarantee that one listener is executed before another.
                // The priorities of the internal Symfony listeners usually range from -256 to 256
                ['setRefreshTokenCookie', -300],
                ['removeRefreshTokenFromResponse', -301]
            ],
            KernelEvents::REQUEST => [['addRefreshTokenToJWTRefreshRequest']],
        ];
    }
}