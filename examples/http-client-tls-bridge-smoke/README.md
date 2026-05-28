# HTTP Client TLS Bridge Smoke

This example is a focused bridge-side smoke for the current `jinguissl_bridge.*` HTTP client TLS gate/startup/verified-session path.

It intentionally keeps the flow narrow:

- one import surface: `jinguissl_bridge.*`
- bridge-side discovery of the current `HTTP_CLIENT_TLS` gate facts
- bridge request wrappers for trust normalization and startup readiness
- TLS1.3 `ClientHello -> serverFlight -> verifiedSession -> runtime` continuation at the bridge facade
- fail-closed hostname-mismatch verification outcome

It does not claim:

- default HTTPS/provider promotion
- raw socket framing or listener attach ownership
- stable HTTP server attach behavior
- upper-layer fallback orchestration ownership

## Run

```bash
cjpm run
```

## Output

The program prints:

- bridge artifact metadata and the advertised single-import path
- the current `HTTP_CLIENT_TLS` gate status, selected entry, fallback target, and observability tags
- trust normalization, startup profile, and startup readiness facts for the HTTP client library lane
- TLS1.3 `ClientHello`, verified session, runtime payload, exporter, and key-update continuation facts
- fail-closed hostname-mismatch verification outcome

## Notes

- This example is intentionally narrower than the bridge tests; it is for HTTP client TLS gate/startup/verified-session consumption only.
- The encoded `ClientHello` is the handshake payload at this layer; raw record/socket framing still belongs to your upper layer.
- The bridge keeps a single import surface for trust/startup/verified-session continuation, but it does not take over fallback orchestration or default HTTPS attach policy.
