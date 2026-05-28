# SSH Library Bridge Smoke

This example is a focused bridge-side smoke for the current `jinguissl_bridge.*` SSH library startup/runtime wrapper path.

It intentionally keeps the flow narrow:

- one import surface: `jinguissl_bridge.*`
- raw banner/KEXINIT bytes stay with the caller
- bridge request wrappers carry the SSH startup inputs into stable startup bundles
- runtime payload protection stays at the returned runtime objects

It does not claim built-in daemon, channel, subsystem, or HTTPS attach behavior.

## Run

```bash
cjpm run
```

## Output

The program prints:

- bridge artifact metadata and the advertised single-import path
- transcript and negotiated-algorithm facts for the SSH startup flow
- server/client startup bundle readiness and verified host-signature state
- bidirectional protected payload flow over the returned runtime objects

## Notes

- This example is intentionally narrower than the bridge test suite; it is for SSH startup/runtime consumption only.
- The example keeps upper-layer ownership honest: you still own banner exchange, packet IO, and any later session/channel/subsystem orchestration.
