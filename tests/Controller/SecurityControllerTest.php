<?php

namespace App\Tests\Controller;

use App\Exception\LogoutNotSupportedWithAuthorizationHeaderTypeTokenExtractorException;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

/**
 * Class SecurityControllerTest
 * @package App\Tests\Controller
 */
class SecurityControllerTest extends AbstractControllerTest
{
    /**
     * @return void
     * @throws \Exception
     */
    public function testLogout()
    {
        $this->runCommand('doctrine:fixtures:load --append --group=UserFixtures');
        $this->output->writeln("\r\n<info>Test the logout route:</info>");
        $this->client->catchExceptions(false);

        // Valid request with ROLE_USER
        $this->output->writeln("\n<info>Valid request with ROLE_USER ...</info>");
        $this->client->request('POST', '/login_check', [], [], [
            'CONTENT_TYPE' => 'application/json'
        ], json_encode(['username' => 'eleven@cvlt.dev', 'password' => 'Eggo']));

        if (!$token = $this->getJsonResponseContentValue('token')) {
            $this->output->writeln("<info>Secure httponly cookie token extractor is enabled ... Great!</info>");
            $this->client->request('GET', '/authorization-tests/user-role');
        } else {
            $this->output->writeln("<error>lexik_jwt_authentication.token_extractors.authorization_header enabled</error>");
            $this->output->writeln("<error>This type of autentication is don't provide security against XSS attacks!</error>");
            $this->output->writeln("<error>more info: https://blog.liplex.de/improve-security-when-working-with-jwt-and-symfony/</error>");
            $this->client->request('GET', '/authorization-tests/user-role', [], [], parent::getAuthHeaders($token));
        }
        $this->assertEquals(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());

        // Logout
        if (!$token) {
            $this->output->writeln("<info>GET /logout: Method Not Allowed (Allow: DELETE)</info>");
            $exceptionThrown = false;
            try {
                $this->client->request('GET', '/logout');
            } catch (MethodNotAllowedHttpException $e) {
                $exceptionThrown = true;
            }
            $this->assertEquals(true, $exceptionThrown);

            $this->client->request('DELETE', '/logout');
            $this->output->writeln("\n<info>Logout requested ...</info>");
            $this->assertEquals(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());

            $this->output->writeln("\n<info>After a logout request, a token refresh request should be denied! (Expected status code:401 (UNAUTHORIZED))</info>");
            $this->client->request('UPDATE', '/token/refresh');
            $this->assertEquals(Response::HTTP_UNAUTHORIZED, $this->client->getResponse()->getStatusCode());
            
            $this->output->writeln("\n<info>Expected exception on authorized route: AccessDeniedException</info>");
            $this->expectException(AccessDeniedException::class);
            $this->client->request('GET', '/authorization-tests/user-role');
        }
        
        $this->output->writeln("\n<error>Backend logout not supported with authorization header type token extractor!</error>");
        $this->output->writeln("<info>Expected exception on logout: LogoutNotSupportedWithAuthorizationHeaderTypeTokenExtractorException</info>");
        $this->expectException(LogoutNotSupportedWithAuthorizationHeaderTypeTokenExtractorException::class);
        $this->client->request('DELETE', '/logout', [], [], parent::getAuthHeaders($token));
    }
}