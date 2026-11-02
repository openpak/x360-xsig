# Protocol: x360-xsig

Live service 12 (`xsig`), XAM 17559.

Request: `u16 length, leaf DER`. Reply (12 bytes): `u32 HRESULT` (0 trusted, 0x80090325 untrusted), `u64
FILETIME` until which XAM may cache the verdict. XAM's TLS provider pauses the WLID handshake for this answer; an
untrusted verdict closes the socket (80151103 at the user logon). The CA comes from x360-xuacs once and is cached;
while xuacs is unreachable the request fails (503) rather than answering untrusted.

## Wharf

Behaviour is carried over from x360-xuacs v0.9.7, where sign-in passes this check in Wharf. The CA is fetched over the internal API.
