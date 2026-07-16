# engage compatibility patch

This directory vendors `age-hpke-pq` 0.0.6 from
`Slurp9187/age-pq-workspace` commit `966d530d33dec94f171634d78b6aa5c97eea89bc`.

The upstream manifest constrained `half` to `>=2.0, <2.5` for an old Rust MSRV workaround, but the
crate does not use `half`. GPUI 0.2.2 uses Naga 25, which requires `half ^2.5`; Cargo cannot resolve
both constraints because they are in the same major-version compatibility range. The vendored
manifest therefore removes only that unused direct dependency. Source code and cryptographic
behavior are unchanged.
