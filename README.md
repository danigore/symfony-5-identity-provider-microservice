1; Just install the dependencies:
---
`$ composer update`

2; Generate the SSH keys:
---
`$ mkdir -p config/jwt`

`$ openssl genpkey -out config/jwt/private.pem -aes256 -algorithm rsa -pkeyopt rsa_keygen_bits:4096`

`$ openssl pkey -in config/jwt/private.pem -out config/jwt/public.pem -pubout`

*Any more info about the **lexik/jwt-authentication-bundle** here:*
[LexikJWTAuthenticationBundle#getting-started](https://github.com/lexik/LexikJWTAuthenticationBundle/blob/master/Resources/doc/index.md#getting-started)

3; And finally test it ...
---
`$ php bin/phpunit`