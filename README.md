# promptsign-node

The **reference implementation** of [PromptSign](https://github.com/PromptSign/spec)
— signing and verification of AI instruction files — written in Node with zero
dependencies.

Its job is to keep the specification honest. One implementation is a
specification of one: whatever that codebase happens to do becomes the de facto
format, bugs included. A second, independent implementation written from the
spec rather than from the first implementation's source is what turns a
document into something you can actually build against. When this and the Rust
implementation disagree, that disagreement is a bug in the spec's clarity — and
finding those before third parties do is the entire point.

It is deliberately readable. Every file maps to a spec section, and the whole
thing is Node standard library, so you can follow the format end to end without
resolving a dependency tree.

## Scope

**This is not a port of the `promptsign` CLI, and it is not the tool to install
for day-to-day use.** It implements the Phase 1 formats only:

| Spec | Implemented |
|---|---|
| [01 — bundle manifest](https://github.com/PromptSign/spec/blob/main/01-manifest.md) | yes |
| [02 — canonicalization](https://github.com/PromptSign/spec/blob/main/02-canonicalization.md) | yes |
| [03 — signature bundle](https://github.com/PromptSign/spec/blob/main/03-bundle.md) | yes, `ed25519` local-key signing |
| [04 — trust policy](https://github.com/PromptSign/spec/blob/main/04-policy.md) | yes, including trust-on-first-use pins |
| [05 — keyless](https://github.com/PromptSign/spec/blob/main/05-keyless.md) | **no** |
| [06 — revocation feed](https://github.com/PromptSign/spec/blob/main/06-revocation.md) | **no** |

Keyless signing needs network access — an OpenID Connect token, a short-lived
Fulcio certificate, a Rekor log entry — which is exactly the kind of dependency
this implementation exists to avoid having. It lives in the `promptsign` CLI
instead.

Encountering a keyless bundle here is **not** silently treated as unsigned: an
unrecognized `signer.scheme` is a hard failure with `unsupported signature
scheme`, per spec 05 §1. Failing closed on formats you do not understand is the
behavior being demonstrated.

The version number reflects this narrower scope and intentionally lags the
Rust implementation.

## Usage

```bash
node src/index.mjs --help

node src/index.mjs keygen --identity "github:alice"
node src/index.mjs sign ./skills/pdf --name acme/pdf --version 1.0.0
node src/index.mjs verify ./skills/pdf
node src/index.mjs verify-tree ~/.claude .claude
```

The package is **`@promptsign/reference`** and the command it installs is
**`promptsign-reference`** — neither is plain `promptsign`, which belongs to the
Rust CLI. Having the reference implementation shadow the real one on `$PATH`,
or turn up first for someone searching the registry, would be a bad day for
somebody.

Exit codes follow the spec: `0` ok (possibly with warnings), `1` usage or
internal error, `2` enforcement failure — the last chosen to match the
block-on-exit-2 contract of Claude Code and Codex hooks.

### As a library

```js
import { verifyTarget } from '@promptsign/reference';
import { canonicalizeMarkdown, digestFile } from '@promptsign/reference/canonicalize';
import { buildManifest } from '@promptsign/reference/manifest';
```

Subpaths `./bundle` and `./policy` are exported too. Working in this repo
directly, import `./src/verify.mjs` and friends by path.

`canonicalizeMarkdown` is the function to read first because canonicalization is the
part of the spec that everyone underestimates, and is the whole reason a signature
survives a Windows checkout.

## Zero dependencies

`package.json` has no `dependencies` key at all. Ed25519 comes from
`node:crypto`, everything else from the standard library. Requires Node ≥ 20.

For a verifier this is a security property rather than a style preference: a
verifier is a trust root the moment anything relies on it, and a trust root
with a supply chain is a contradiction. It also means the implementation can be
read in an afternoon, which a reference implementation has to be.

## Testing

```bash
npm test        # node --test
```

Wire-format agreement with the other implementation is checked separately, by
the conformance suite in the spec repository:

```bash
IMPL_A="node src/index.mjs" IMPL_B="/path/to/promptsign" IMPL_B_SIGN_ARGS="--local-key" \
  bash ../spec/test/conformance.sh
```

It signs with each implementation and verifies with the other, in both
directions, then compares canonical digests, policy verdicts, and `verify-tree`
output byte for byte. Supplying only `IMPL_A` runs the one-sided checks and
skips the rest.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
