# login.jamesward.dev

This sample has a Spring Auth server providing auth to the MCP server.

It includes some production oriented aspects:
- Disable OAuth Consent (assuming you want that UX)
- Long-lived tokens so user doesn't have to re-auth often
- Prod stable JWT private key
- Custom UI with JTE & pre-compiled templates for login server
- Virtual threads

## Auth Server

Run the auth server:
```
./gradlew bootRun
```

Test the login flow by opening `http://localhost:9000/`

Demo user: `demo`
Demo password: `pw`

By default the server generates a random RSA key pair on each startup, which invalidates existing tokens on restart. For production, set `JWK_RSA_PRIVATE_KEY` to use a stable key.

Generate a key:
```
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform PEM -out jwk-private.pem
```

Set the env var (the value is the full PEM including headers):
```
export JWK_RSA_PRIVATE_KEY="$(cat jwk-private.pem)"
```

Then delete the file:
```
rm jwk-private.pem
```

Generate a prod container:
```
./gradlew bootBuildImage
```

