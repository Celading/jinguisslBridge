# HTTP Server Attach Planning Bridge Smoke

This example is a focused bridge-side smoke for the current `jinguissl_bridge.*` HTTP server attach planning path.

It intentionally keeps the flow narrow:

- one import surface: `jinguissl_bridge.*`
- bridge-side discovery of the current `HTTP_SERVER_ATTACH_PLANNING` gate facts
- bridge request wrappers for server TLS config validation and normalized material preparation
- bridge-side startup bundle readiness for the server library lane
- fail-closed `HTTP_SERVER_STABLE_ATTACH` blocked outcome

It does not claim:

- stable listener attach ownership
- direct `stdx.net.tls.TlsServerConfig` bridging
- default HTTPS/provider promotion
- upper-layer listener lifecycle orchestration ownership

## Run

```bash
cjpm run
```

## Output

The program prints:

- bridge artifact metadata and the advertised single-import path
- planning gate status, attach boundary facts, and blocked stable-attach gate evidence
- normalized server TLS validation/material facts such as ALPN, chain length, and PEM block count
- HTTP server library startup profile/readiness facts at the bridge surface
- deterministic fail-closed outputs for missing `h2` ALPN and certificate/key mismatch

## Notes

- This example is intentionally narrower than the bridge tests; it is for planning-only server attach evidence, not published listener attach.
- The bridge keeps validation/material/startup facts on one import surface, but final listener attach still belongs to upper-layer glue such as `lisi/stdx`.
- A blocked stable-attach outcome is part of the expected output, not a regression.
