# Evidence Fusion & Intent-Aware Review

Waibon Dev Shield v0.6.0 uses multiple evidence layers before assigning review priority.

## Layers

1. Text Evidence: raw commands, tokens, strings, config and workflow patterns.
2. Context Evidence: whether the evidence appears in active code, docs, examples, tests, placeholders, detector rules, generated output, or lock files.
3. Behavior Evidence: what the code appears capable of doing, such as download, execute, read secrets, modify security settings, persist, or publish.
4. Chain Evidence: whether multiple behaviors connect into a stronger sequence, such as download -> execute -> persist.
5. Intent Evidence: inferred purpose from combined evidence. This is a review signal, not a claim of certainty.

## Why this matters

Security reports can harm trust if they overstate weak evidence. v0.6.0 is designed to reduce that risk by treating text matches as raw evidence and requiring combined evidence for higher severity.
