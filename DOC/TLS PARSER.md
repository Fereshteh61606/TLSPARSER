# TLS
**Transport Layer Security (TLS)** is a cryptographic protocol designed to provide communications security over a computer network. The protocol is widely used in applications such as email, instant messaging, and voice over IP, but *its use in securing HTTPS remains the most publicly visible*.

The TLS protocol aims primarily to provide security, including privacy (confidentiality), integrity, and authenticity through the use of cryptography, such as the use of certificates, between two or more communicating computer applications.

**TLS runs in the presentation layer and is itself composed of two layers: the *TLS record* and the *TLS handshake protocols*.**

# Record
Each record has: 
1. a content type field that designates the type of data encapsulated
Content types

| Hex 	| Dec 	| Type |
|--------|-------|-------|
| 0×14 	 |20 	 |ChangeCipherSpec
| 0×15 	| 21 	| Alert
| 0×16 	| 22 	| Handshake
| 0×17 | 23 	| Application
| 0×18 	| 24 	| Heartbeat 


2. a length field 
3. a TLS version field.

| Majorversion | Minorversion 	| Version type | 
|------| -------| -------|
| 3 	| 0 	| SSL 3.0
| 3 	| 1 	| TLS 1.0
| 3 	| 2 	| TLS 1.1
| 3 	| 3 	| TLS 1.2
| 3 	| 4 	| TLS 1.3 

# TLS handshake
When the connection starts, the record encapsulates a "control" protocol – the handshake messaging protocol (content type 22). This protocol is used to exchange all the information required by both sides for the exchange of the actual application data by TLS

| Message types Code 	| Description | 
|-----------------------|---------------|
| 0 	| HelloRequest
| 1 	| ClientHello
| 2 	| ServerHello
| 4 	| NewSessionTicket
| 8 	| EncryptedExtensions (TLS 1.3 only)
| 11 	| Certificate
| 12 	| ServerKeyExchange
| 13 	| CertificateRequest
| 14 	| ServerHelloDone
| 15 	| CertificateVerify
| 16 	| ClientKeyExchange
| 20 	| Finished 


to learn how to parse the data visit [Bytes Description in handshake](https://tls13.xargs.org/)

and to to findout about parsing the server hello look at the  [Bytes Description of server certificate](https://tls12.xargs.org/certificate.html#server-certificate-detail)