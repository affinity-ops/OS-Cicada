#!/usr/bin/env python3
"""
Add copyright headers to all proprietary source files in the Cicada project.
Run from the project root:  python3 scripts/add_copyright_headers.py

Headers are NOT added to:
- node_modules/, vendor/, .venv/, build/, .dart_tool/ (third-party)
- .git/ (version control)
- Generated files (*.g.dart, *.freezed.dart)
- Markdown/docs (they're docs, not code)
"""

import os
import sys

PROJECT_ROOT = "/Users/patrickmatthews/Downloads/Web Dev - Patrick/Cicada Project"

HEADER_GO = """// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
"""

HEADER_DART = """// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
"""

HEADER_PYTHON = """# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""

HEADER_PHP = """<?php
/**
 * © 2026 Affinity Ops Ltd. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
"""

HEADER_TS = """// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
"""

HEADER_TSX = """// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
"""

HEADER_JS = """// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
"""

HEADER_YAML = """# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""

EXCLUDE_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "build", ".dart_tool",
    ".next", ".turbo", ".idea", "recovery_apk", "corrupted_backup",
    "logs", "project ui assets", "scratch", "test-results",
    "playwright-report", "apk_server", "data", "scripts",
}

EXCLUDE_FILES = {
    "*.g.dart", "*.freezed.dart", "*.config.dart", ".env", ".env.example",
    "pubspec.lock", "package-lock.json", "composer.lock", "Cargo.lock",
    "go.sum", ".lic", "sentry_ed25519.key", "master_keys.json",
}

HEADERS = {
    ".go": HEADER_GO,
    ".dart": HEADER_DART,
    ".py": HEADER_PYTHON,
    ".php": HEADER_PHP,
    ".ts": HEADER_TS,
    ".tsx": HEADER_TSX,
    ".js": HEADER_JS,
    ".yaml": HEADER_YAML,
    ".yml": HEADER_YAML,
}


def should_exclude(dir_path, root):
    rel = os.path.relpath(root, PROJECT_ROOT)
    parts = rel.split(os.sep)
    return any(p in EXCLUDE_DIRS for p in parts)


def has_header(content, header):
    """Check if the first N chars contain the header (handles shebang, <?php, etc.)"""
    first_line = content.lstrip().split('\n')[0]
    # Check for any line containing "Affinity Ops" or "Proprietary"
    for line in content.split('\n')[:10]:
        if "Affinity Ops" in line or "Proprietary and confidential" in line:
            return True
    return False


def add_header(filepath, header):
    with open(filepath, 'r') as f:
        content = f.read()

    if not content.strip():
        return False  # Empty file — skip

    if has_header(content, header):
        return False  # Already has a copyright header

    # Handle shebang files (Python scripts)
    if content.startswith('#!'):
        # Insert header after shebang
        newline_idx = content.index('\n')
        new_content = content[:newline_idx+1] + '\n' + header + content[newline_idx+1:]
    # Handle <?php files
    elif content.startswith('<?php'):
        new_content = header + content[6:].lstrip()
    else:
        # Dart lint requires header before imports
        # Go also doesn't mind headers at the top
        new_content = header + '\n' + content

    with open(filepath, 'w') as f:
        f.write(new_content)

    return True


def main():
    added = 0
    skipped = 0
    errors = 0

    for root, dirs, files in os.walk(PROJECT_ROOT):
        # Prune excluded dirs
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        if should_exclude(root, PROJECT_ROOT):
            continue

        for filename in files:
            filepath = os.path.join(root, filename)
            ext = os.path.splitext(filename)[1]

            # Skip excluded patterns
            skip = False
            for pattern in EXCLUDE_FILES:
                if pattern.startswith("*."):
                    if ext == pattern[1:]:
                        skip = True
                        break
                elif filename == pattern:
                    skip = True
                    break
            if skip:
                continue

            header = HEADERS.get(ext)
            if header is None:
                continue

            try:
                if add_header(filepath, header):
                    print(f"  + {os.path.relpath(filepath, PROJECT_ROOT)}")
                    added += 1
                else:
                    skipped += 1
            except Exception as e:
                print(f"  ! {os.path.relpath(filepath, PROJECT_ROOT)}: {e}", file=sys.stderr)
                errors += 1

    print(f"\nDone. Added headers: {added}, Skipped (already had): {skipped}, Errors: {errors}")


if __name__ == "__main__":
    main()