# Trust Workflow

The trust workflow lets a user reduce review priority for known, expected findings after human review.

Create `.waibon-trust.json` in the target repository root. Supported entries:

- `trusted_files`: exact files, path prefixes ending in `/`, or simple `*` patterns
- `trusted_rules`: rule IDs that are expected in this repository
- `trusted_pairs`: a file and rule ID pair
- `trusted_fingerprints`: stable finding fingerprints copied from reports

A trusted finding is not deleted or hidden. It is reduced to INFO and marked with `trusted=true` and `trust_reason`.
