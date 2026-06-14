# Security Notes - Waibon Dev Shield v0.6.0

Waibon Dev Shield is a local, report-only developer safety scanner.

It does **not** claim that a file or repository is malware from a single pattern match. It reports evidence-based review signals and helps users prioritize human review.

## Default safety behavior

- Does not delete files
- Does not modify files
- Does not quarantine files
- Does not execute target project files
- Does not upload project contents
- Generates local reports only

## Severity policy

Red / CRITICAL is reserved for high-proof evidence such as:

- real secret plus exfiltration-like chain,
- private-key proof in active context,
- strong destructive chain,
- strong download -> execute -> persistence chain,
- or comparable multi-layer evidence.

Warnings and review findings should be interpreted as review priorities, not verdicts.

## False positives

Security reports can harm trust if they overstate weak evidence. Waibon Dev Shield separates raw signals from unique review issues and root-cause review groups to reduce over-reporting.

If a finding appears in docs, tests, examples, placeholders, detector rules, or generated files, the scanner may reduce review priority through context evidence.
