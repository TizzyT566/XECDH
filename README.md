# XECDH
(Cross Elliptic Curve Diffie-Hellman)

A cryptographic scheme which validates client and server via a shared key derived from crossing 2 static Elliptic Curve pairs, each held by the client and server respectively coupled with an emphemeral pair during the handshake.

Intended Scheme:
Upon first ever connection, the server is to send its public key to the client and the client sends their public key to the server.
For subsequent connections the server and client will generate a new keypair (for ephemeral purposes) and exchange their public keys.
The obtained public key is to be used to derive an intermediate shared key.
The 2 derived keys are then concatinated to each other and hashed to be used as the AES key/iv.
