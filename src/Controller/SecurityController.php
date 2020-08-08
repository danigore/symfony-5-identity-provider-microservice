<?php

namespace App\Controller;

use App\Service\DependencyInjection\LexikJWTAuthenticationDependencyInjectionService;
use App\Exception\LogoutNotSupportedWithAuthorizationHeaderTypeTokenExtractorException;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Yaml\Exception\ParseException;

/**
 * Class SecurityController
 * @package App\Controller
 */
class SecurityController
{
    /**
     * @Route("/logout", name="app_logout", methods={"GET"})
     * @param LexikJWTAuthenticationDependencyInjectionService $service
     * @return JsonResponse
     * @throws ParseException
     * @throws LogoutNotSupportedWithAuthorizationHeaderTypeTokenExtractorException
     */
    public function logout(LexikJWTAuthenticationDependencyInjectionService $service): JsonResponse
    {
        if ($service->isAuthorizationHeaderExtractorEnabled()) {
            throw new LogoutNotSupportedWithAuthorizationHeaderTypeTokenExtractorException('Backend logout not supported!');
        }

        $response = new JsonResponse(null, Response::HTTP_OK);
        $response->headers->setCookie(new Cookie($service->getCookieName(), '', 1));
        $response->send();

        return $response;
    }
}