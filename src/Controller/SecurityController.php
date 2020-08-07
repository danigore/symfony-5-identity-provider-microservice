<?php

namespace App\Controller;

use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use App\Exception\LogoutNotSupportedWithAuthorizationHeaderTypeTokenExtractorException;

/**
 * Class SecurityController
 * @package App\Controller
 */
class SecurityController
{
    private bool $authorizationHeaderEnabled;

    /**
     * SecurityController constructor.
     * @param ParameterBagInterface $params
     * @throws ParseException
     */
    public function __construct(ParameterBagInterface $params)
    {
        $lexikJwtConfig = Yaml::parseFile($params->get('kernel.project_dir').'/config/packages/lexik_jwt_authentication.yaml');
        $this->authorizationHeaderEnabled = !empty($lexikJwtConfig['lexik_jwt_authentication']['token_extractors']['authorization_header']['enabled']);
    }

    /**
     * @Route("/logout", name="app_logout", methods={"GET"})
     * @return JsonResponse
     * @throws LogoutNotSupportedWithAuthorizationHeaderTypeTokenExtractorException
     */
    public function logout(): JsonResponse
    {
        if ($this->authorizationHeaderEnabled) {
            throw new LogoutNotSupportedWithAuthorizationHeaderTypeTokenExtractorException('Backend logout not supported!');
        }

        $response = new JsonResponse(null, Response::HTTP_OK);
        $response->headers->setCookie(new Cookie('BEARER', '', 1));
        $response->send();

        return $response;
    }
}