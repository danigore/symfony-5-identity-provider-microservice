<?php

namespace App\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\IsGranted;

/**
 * Class AuthorizationTestRoutesController
 * @package App\Controller
 * @Route("/authorization-tests")
 */
class AuthorizationTestRoutesController
{
    /**
     * @Route("/user-role", name="user_role_check", methods={"GET"})
     * @param Request $request
     * @return JsonResponse
     */
    public function userRoleRequired(Request $request): JsonResponse
    {
        return new JsonResponse(null, Response::HTTP_OK);
    }

    /**
     * @Route("/admin-role", name="admin_role_check", methods={"GET"})
     * @IsGranted("ROLE_ADMIN")
     * @param Request $request
     * @return JsonResponse
     */
    public function adminRoleRequired(Request $request): JsonResponse
    {
        return new JsonResponse(null, Response::HTTP_OK);
    }
}