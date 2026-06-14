# Accuracy + False Positive Reduction

v0.6.0 reduces noisy findings by checking context before raising risk.

The scanner labels findings by false-positive class:

- Active code or config
- Documentation, examples, tests, or markdown
- Detector rule / security scanner config
- Placeholder, sample, or empty assignment
- Generated, lockfile, or build output
- Comment-only context

CRITICAL is reserved for stronger proof such as a real token/private key or a strong behavior chain.
