This is a Symfony 5 microservice skeleton with stateless, logout and refreshable JWT authentication, with secure http-only cookie token extractor and database-less user provider.

1; Update dependencies:
---
`$ composer update`

2; Generate your SSH keys:
---
`$ mkdir -p config/jwt`

`$ openssl genpkey -out config/jwt/private.pem -aes256 -algorithm rsa -pkeyopt rsa_keygen_bits:4096`

`$ openssl pkey -in config/jwt/private.pem -out config/jwt/public.pem -pubout`

*Any more info about the **lexik/jwt-authentication-bundle** here:*
[LexikJWTAuthenticationBundle#getting-started](https://github.com/lexik/LexikJWTAuthenticationBundle/blob/master/Resources/doc/index.md#getting-started)

2; And finally test it ...
---
`$ php bin/phpunit`

*The `./bin/phpunit` command is created by Symfony Flex when installing the phpunit-bridge package. If the command is missing, you can remove the package (`composer remove symfony/phpunit-bridge`) and install it again. **Another solution is to remove the project’s symfony.lock file and run** `composer install` to force the execution of all Symfony Flex recipes.*


> #### Additionally
>
> **Originally enabled the secure http-only cookie token extractor** (to provide security against XSS attacks):
> [LexikJWTAuthenticationBundle/1-configuration-reference.md#automatically-generating-cookies](https://github.com/lexik/LexikJWTAuthenticationBundle/blob/master/Resources/doc/1-configuration-reference.md#automatically-generating-cookies)
>
> *... but the shift back to the authorization header type extractor is easy to, just update the lexik_jwt_authentication config file by this commit:*
> [commit/Extended lexik_jwt_authentication configuration](https://github.com/danigore/symfony-5-microservice-auth/commit/6a952b83af99340c7335ef0cc276c5a18058272f)
>
> ***More info about why is the combination of JWT and XSS so relevant***:
> [Christian Kolb:Improve security when working with JWT and Symfony](https://blog.liplex.de/improve-security-when-working-with-jwt-and-symfony/)