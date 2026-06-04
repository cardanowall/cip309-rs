# Security Policy

`cardanowall` is the Rust SDK for Label 309, a standard for cryptographic Proof of
Existence. Its security properties matter to everyone who relies on a proof, so
we take reports seriously and ask that they be handled responsibly.

## Scope

This repository holds the **Rust implementation** (crate `cardanowall`): the
structural validator, public verifier, recipient verifier with sealed-PoE
decryption, the cryptographic primitives, and the gateway-agnostic HTTP client.

In scope for a report here:

- A flaw in this crate that lets a verifier be misled into accepting an invalid
  proof, decrypt something it should not, leak information it should not, or that
  weakens the secure-by-default HTTP egress (SSRF guard, deny-host policy,
  bounded bodies/timeouts).
- A divergence between this crate and the canonical conformance vectors that
  enshrines an insecure behaviour.

Out of scope here (report it in the relevant repository instead):

- A flaw or ambiguity in the **standard** itself — report it in the `label-309`
  standard repository.
- A bug in another implementation — `label-309-ts`, `label-309-py`, or the
  `label-309-cli` command-line tool. Use that repository's security policy.

## Core security goals

A report is **high priority** if it undermines any of the standard's core
guarantees as realised by this crate:

- **Standalone verifiability** — a proof verifies from the transaction metadata,
  the optional content bytes, and a public blockchain explorer alone.
- **Zero issuer trust** — verifying a proof never requires trusting the
  publisher, their domain, or any server.
- **Confidentiality of sealed PoE** — only an intended recipient can decrypt a
  sealed payload, and trial-decryption does not leak which recipient matched.
- **Algorithm agility done safely** — registry additions cannot weaken existing
  records or enable downgrade.

## Reporting a vulnerability

**Please report privately. Do not open a public issue for a security report.**

Preferred channel: GitHub's **private vulnerability reporting** for this
repository (the *Security* tab → *Report a vulnerability*).

Alternative contact: `hello@cardanowall.com`.

Please include, as far as you can:

- A clear description of the issue and the security property it breaks.
- The exact location — module, function, or test — and a minimal reproduction.
- The impact and, if you have one, a suggested remediation.

## What to expect

- We aim to acknowledge a report promptly and to keep you informed as we
  investigate.
- We practise **coordinated disclosure**: we will agree a disclosure timeline
  with you, fix the issue, and credit you unless you prefer otherwise.
- Because this crate is **pre-1.0**, there are no long-term-supported released
  versions yet; fixes land on the current line.

Thank you for helping keep Label 309 trustworthy.
