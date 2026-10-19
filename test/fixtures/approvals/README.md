# Approval fixtures

Shared fixtures for the [09](../../../09-approvals.md) conformance checks.

`listing.txt` is the content listing (§1) of the skill that `conformance.sh`
builds with `mkskill`. Its SHA-256,
`38209d34368a5cc6ade9034887f7fa314647e657153dfdee0b13f543c410fa9a`, is the
skill's content digest.

The approvals come from the `acme` test deployment of
[../rekor-v2](../rekor-v2/README.md); install its root first with
`promptsign trust add acme-v2 --trusted-root ../rekor-v2/trusted_root.json --yes`.
Each was signed keyless (issuer `https://sso.acme.test`) at
2026-10-01T12:00:00Z.

| File | Carriage | Verdict |
|---|---|---|
| `bob.json` | PromptSign keyless bundle, Rekor v1 entry | approves the skill, `bob@acme.test`, root `acme-v2` |
| `carol.sigstore.json` | Sigstore bundle v0.3, Rekor v2 entry and a timestamp, as cosign writes it | approves the skill, `carol@acme.test`, root `acme-v2` |
| `other-content.json` | PromptSign keyless bundle | verifies, but approves other content, so it does not count |

`promptsign-core`'s `tests/conformance_fixtures.rs` wrote the JSON files. Its
times are fixed and its signatures deterministic, so regenerating writes the
same bytes:

```bash
PROMPTSIGN_APPROVAL_FIXTURES_OUT=<this directory> \
  cargo test --test conformance_fixtures write_approval_fixtures -- --ignored
```

The repository stores this tree with `-text`: a line-ending conversion would
break every signature in it.
