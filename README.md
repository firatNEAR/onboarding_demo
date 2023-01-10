# NEAR onboarding experience demo 

This is a working skeleton of a Node.js/Koa application with passwordless NEAR account creation and sending NEAR to a master account on localnet.

Main version (Koa/fido2-lib) live at [https://56k.guru/webauthn](https://56k.guru/webauthn)
Deno version (Deno/Opine/fido2-lib) live at [https://56k.guru/webauthn-deno](https://56k.guru/webauthn-deno)

## Features

*  Create NEAR accounts using FIDO2 create flow
*  Send a test transaction to the network through using 'Login' button on UI


Using Koa and fido2-lib

## Versions

There are multiple versions of this demo available in different branches

| Runtime | Server framework | Branch | Webauthn-lib | Live at |
| ------- | ---------------- | ------ | ------------ | ------- |
| Node | Koa | [main](https://github.com/Hexagon/webauthn-skeleton) | [fido2-lib](https://www.npmjs.com/package/fido2-lib) | [56k.guru/webauthn](https://56k.guru/webauthn) |
| Node | Express | [server/express](https://github.com/Hexagon/webauthn-skeleton/tree/server/express) | [fido2-lib](https://www.npmjs.com/package/fido2-lib) | - |
| Deno | Opine | [server/deno](https://github.com/Hexagon/webauthn-skeleton/tree/server/deno) | [fido2-lib](https://www.npmjs.com/package/fido2-lib) | [56k.guru/webauthn-deno](https://56k.guru/webauthn-deno) |

## Getting it running

First clone this repo, then:

### 1. Install dependencies

```npm install```

### 2. Generate self signed certificate and keys (webauthn requires HTTPS)

**I repeat, you need to generate keys, certificate and serve using https for webauthn to work**

```
cd keys

openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -subj '/CN=localhost'
openssl genrsa -out key.pem
openssl req -new -key key.pem -out csr.pem
openssl x509 -req -days 9999 -in csr.pem -signkey key.pem -out cert.pem

rm csr.pem

cd ..
```

### 3. Start server 

```node app```

### 4. Open browser

```https://localhost:3010```

