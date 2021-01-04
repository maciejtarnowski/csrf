# csrf

HMAC Based CSRF Tokens

## Description

The package uses HMAC based on SHA-512/224 to generate CSRF tokens that:
* do not need to be stored anywhere on the backend,
* include their expiration date,
* can be easily validated by the server (with the secret used to generate the token).

## Usage

### Variables

#### Session ID

Good tokens should work for a single user and a single operation.

To achieve that, use a _Session ID_ value that includes:
* **user identifier**, so token generated for _user A_ cannot be used by _user B_,
* **operation or form name**, so token generated for _operation X_ cannot be used when performing _operation Y_.

#### Expiration date

Tokens should not be valid for too long.

You need to determine the TTL suitable for your use-case.
Tokens carry their expiration date, so the TTL can vary between operations (forms),
for example: a token used in a login form can be generated to expire after 5 minutes,
but a token in a search form can live for one hour.

Generally, an hour or two is the sensible maximum.

#### Secret

The _secret_ is what makes the tokens safe and tamperproof.
As long as the _secret_ is not exposed outside the application and its value is hard to guess,
only the server can generate valid tokens.

For the tokens to work, you need to use the same secret for generating and validating the token.

Use a long (40 chars+), random string as your secret and keep it safe.

### Generate a token

```go
// example: "user" + user_id + operation
sessionId := "user_123_login"

// generate a token for given sessionId, that is valid for one hour and uses "MySuperSecretKey" as the secret
token := csrf.GenerateToken(sessionId, time.Now().Add(time.Hour), "MySuperSecretKey")
```

### Validate a token

```go
// example: "user" + user_id + operation
sessionId := "user_123_login"

token := "4ef3ec3816c4a6fb5b5f2465e128c28f55ec42b34b5d99d21836674c.1609787986"

if csrf.ValidateToken(token, sessionId, time.Now(), "MySuperSecretKey") {
    fmt.Println("token is valid")
} else {
    fmt.Println("token is invalid")
}
```

## License

MIT

```
The MIT License (MIT)

Copyright (c) 2021 Maciej Tarnowski

Permission is hereby granted, free of charge,
to any person obtaining a copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software,
and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies
or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

## Further reading

* https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#hmac-based-token-pattern
* https://www.nedmcclain.com/better-csrf-protection/
