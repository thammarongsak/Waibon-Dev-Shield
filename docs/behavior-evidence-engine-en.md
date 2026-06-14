# Behavior Evidence Engine

The Behavior Evidence Engine is designed to reduce false positives by grouping raw findings into behavior categories, context flags, and missing-evidence notes.

It does not prove malware. It prioritizes human review.

Main behavior groups include download intent, execution intent, persistence intent, credential or secret exposure intent, possible exfiltration chain, destructive or ransomware-like intent, security-setting modification, supply-chain install surface, CI/CD workflow surface, and AI agent instruction surface.

A behavior chain has more review weight than a single keyword. Context such as docs, examples, tests, placeholders, comments, or detector-rule files can reduce review priority.
