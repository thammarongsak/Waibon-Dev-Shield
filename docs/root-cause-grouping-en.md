# Root Cause Grouping

Waibon Dev Shield v0.6.0 separates raw signals from review issues.

- Raw signals are individual text or rule matches.
- Unique review issues group repeated signals by file, rule, and inferred intent.
- Critical root causes and warning issues are grouped review priorities, not accusations.

This helps avoid overstating risk when the same script, workflow, or example produces many repeated matches.
