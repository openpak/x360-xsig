# Xbox 360 Signature and Certificate Server

OpenPak's Xbox 360 signature and certificate server (Live service 12, `xsig`).

| | |
| --- | --- |
| Network | Xbox 360 |
| Role | Certificate validation for the Windows Live ID TLS connection of the sign-in |
| Depends on | [`x360-common`](https://github.com/openpak/x360-common) (vendored); [`x360-xuacs`](https://github.com/openpak/x360-xuacs) internal API (the WLID TLS front CA) |
| Image | `ghcr.io/openpak/x360-xsig` |
| Used by | XAM through the security gateway |
| Licence | AGPL-3.0-only |

## What it serves

| Path | XRL | What |
| --- | --- | --- |
| `POST /xsig/ValidateCertificate.ashx` | 0xC0B | Is this TLS leaf trusted? Yes when the WLID front CA signed it |
| `GET /healthz` | | Health probe |

Identity headers (`X-X360-Account`, `X-X360-Users`) are trusted only with `X360_GATEWAY_KEY`. Split out of
[`x360-xuacs`](https://github.com/openpak/x360-xuacs), one repository per Live service.

## Run

```sh
GOWORK=off go run -mod=vendor ./cmd/x360-xsig
```

Configuration:

- `X360_XUACS_INTERNAL_URL / _KEY`: xuacs internal API

## Docs

- [Protocol](docs/protocol.md)
- [Evidence](docs/evidence.md)
- [Deploy](docs/deploy.md)

## Licence

AGPL-3.0-only. See [LICENSE](LICENSE).
