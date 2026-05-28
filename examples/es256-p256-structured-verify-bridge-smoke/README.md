# ES256 / P-256 Structured Verify Bridge Smoke

This example is a focused bridge-side smoke for the current `jinguissl_bridge.*` ES256 / P-256 structured verify wrapper path.

It intentionally keeps the flow narrow:

- one import surface: `jinguissl_bridge.*`
- caller-owned structured fields: `x`, `y`, `signedBytes`, `derSignature`
- bridge request/result/outcome shape for success, non-verified success, and malformed-signature failure

It does not claim:

- COSE or CBOR parsing ownership
- WebAuthn ceremony ownership
- default HTTPS/provider promotion
- stable server attach behavior

## Run

```bash
cjpm run
```

## Output

The program prints:

- bridge artifact metadata and the advertised single-import path
- successful ES256 / P-256 signature verification outcome
- fail-closed "signature did not verify" outcome for tampered bytes
- fail-closed error-code mapping for malformed DER signature input

## Notes

- This example is intentionally narrower than the bridge tests; it is for shaped verify input consumption only.
- Upper layers still own parser work and ceremony semantics. The bridge only consumes already-structured key/signature/message fields.
