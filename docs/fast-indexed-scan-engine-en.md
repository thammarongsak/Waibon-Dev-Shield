# Smart Indexed Scan Engine (v0.6.0)

Waibon Dev Shield v0.6.0 improves scan speed without lowering the review model. It does this by using staged scanning:

1. **Metadata / candidate index** — collect candidate file metadata and skip known build/cache folders.
2. **Cache-first reuse** — reuse results for unchanged files.
3. **Cheap content prefilter** — quickly check for behavior-related terms before running heavier rules.
4. **Behavior deep scan** — run full rule matching only on files with behavior signals.
5. **Context reduction** — reduce review priority for docs, tests, examples, placeholders, and detector-rule contexts.

This tool is still report-only. It does not delete, modify, quarantine, or execute target files. Findings are behavior-risk signals, not malware verdicts.
