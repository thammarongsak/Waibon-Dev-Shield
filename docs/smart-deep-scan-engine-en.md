# Smart Deep Scan Engine

Smart Deep Scan is the recommended detailed review mode. It is designed to be more accurate than Quick Scan while avoiding the cost of a full heavy scan over every low-signal file.

Pipeline:

1. Metadata and candidate collection.
2. Cheap prefilter over candidate files.
3. Heavier behavior evidence checks only on higher-signal files.
4. Context reduction for docs, examples, tests, placeholders, and detector-rule files.
5. Behavior summary and HTML/TXT/JSON reports.

Smart Deep is still report-only. It does not delete, modify, quarantine, or execute target files.
