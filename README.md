# ntlm-client

A node.js NTLM client with support for NTLM and NTLMv2 authentication

```
npm install ntlm-client
```

## API

#### createType1Message([workstation, target])

Creates a type 1 NTLM message to initialize the NTLM handshake

- Arguments
  - `workstation` Optional. If `undefined`, `os.hostname()` will be used
  - `target` Optional. This is the domain/host we are trying to authenticate against.
- Returns
  - `string` Complete NTLM string that should be sent to the server in the `Authorization` header

---

#### decodeType2Message(str)

Decodes a type 2 message received from the server including the NTLM challenge

- Arguments
  - `str` Either the base64 encoded type 2 message, or the complete `WWW-Authenticate` header, or an object containg the response headers (`http.IncomingMessage`)
- Returns
  - `type2Message` An object containing the following information about the received type 2 message: `flags`, `encoding`, `version`, `challenge`, `targetName`, `targetInfo`.

---

#### createType3Message(type2Message, username, password[, workstation, target])

Creates a type 3 message based on the type 2 message received from the server.

- Arguments
  - `type2Message` The decoded type 2 message object
  - `username`
  - `password`
  - `workstation` Optional. If falsy, `os.hostname()` will be used
  - `target` Optional. If falsy, the target name from the type 2 message will be used. This is the domain/host we are trying to authenticate against.
- Returns
  - `string` Complete NTLM string that should be sent to the server in the `Authorization` header
