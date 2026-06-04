# Contributing to the Label 309 Rust SDK

Thank you for your interest in improving `cardanowall`, the Rust implementation
of **Label 309** — an open standard for **Proof of Existence (PoE)** anchored on
the Cardano blockchain.

This crate is **pre-1.0**. It is a **byte-parity twin** of the TypeScript and
Python SDKs: all three reproduce the same canonical-CBOR bytes, validation
verdicts, and cryptographic outputs, proven against the **same shared
conformance vectors** vendored under `tests/fixtures/`.

All contributions are made under the terms in [Licensing](#licensing) and the
[Developer Certificate of Origin](#developer-certificate-of-origin-dco).

---

## What belongs in this repository

This repository is the **Rust SDK** for Label 309. Bug fixes, performance work,
new SDK surface, and Rust-specific issues belong here.

What does **not** belong here:

- **Changes to the wire format, grammar, schemas, registries, or the
  conformance vectors** belong in the `label-309` standard repository. The vectors
  are authoritative; a divergence between this crate and a vector is a bug in
  the crate, not the vector.
- **Issues in another implementation** belong in its repository — `label-309-ts`
  (npm), `label-309-py` (PyPI), or `label-309-cli` (the command-line tool).

If you are unsure, open an issue here and ask.

---

## Building and testing

A recent stable Rust toolchain is all you need; the crate has no system
dependencies beyond the OS CSPRNG and uses `rustls` for TLS (no OpenSSL).

```sh
cargo build --all-targets --all-features
cargo test --all-features          # full suite, including the vendored vectors
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

CI runs exactly these. A pull request must pass all four.

### Conformance and byte-parity

Cross-implementation **byte-parity** is a core guarantee of Label 309. The vectors
in `tests/fixtures/` are byte-identical to those the TypeScript and Python SDKs
load. Do not edit a vector to make a test pass: a vector mismatch means this
crate diverged from the standard. If you believe a vector itself is wrong, raise
it in the `label-309` standard repository — the vectors live there canonically.

---

## Pull request checklist

- [ ] The change is in the right repository (this SDK vs. the standard vs.
      another implementation).
- [ ] `cargo test`, `cargo clippy -D warnings`, and `cargo fmt --check` all pass.
- [ ] No conformance vector was edited to force a test to pass.
- [ ] New behaviour is covered by a test; parity-affecting behaviour is pinned
      against the shared vectors.
- [ ] Every commit is signed off (see DCO below).

---

## Style and house rules

- Write for an audience that may implement the standard independently. Public
  API docs must be precise and self-contained.
- Keep the crate **vendor-neutral**. The SDK targets no default gateway host;
  do not write behaviour around any particular hosted service.
- Cite only stable, public references — RFCs, CIPs at a permanent address,
  NIST/FIPS publications, BIPs, and the like.

---

## Developer Certificate of Origin (DCO)

This project uses the **Developer Certificate of Origin**. There is **no CLA**.

The DCO is a lightweight attestation that you have the right to submit your
contribution under the project's license. You make it by adding a
`Signed-off-by` line to every commit:

```
Signed-off-by: Your Name <your.email@example.com>
```

Add it automatically with `git commit -s`. The name and email must be real and
match the commit author. By signing off, you certify the statements in the
Developer Certificate of Origin, version 1.1:

> **Developer Certificate of Origin, Version 1.1**
>
> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I have the
> right to submit it under the open source license indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best of my
> knowledge, is covered under an appropriate open source license and I have the
> right under that license to submit that work with modifications, whether
> created in whole or in part by me, under the same open source license (unless
> I am permitted to submit under a different license), as indicated in the file;
> or
>
> (c) The contribution was provided directly to me by some other person who
> certified (a), (b) or (c) and I have not modified it.
>
> (d) I understand and agree that this project and the contribution are public
> and that a record of the contribution (including all personal information I
> submit with it, including my sign-off) is maintained indefinitely and may be
> redistributed consistent with this project or the open source license(s)
> involved.

---

## Licensing

By contributing, you agree that your contributions are licensed under the
project's **Apache License 2.0** (see [`LICENSE`](LICENSE)).

---

## Code of Conduct

All participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
Please read it before contributing.

## Security

Do not report security-impacting issues through public issues or pull requests.
Follow the private process in our [Security Policy](SECURITY.md).
