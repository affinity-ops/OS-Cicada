#!/usr/bin/env bash
# © 2026 Patrick Matthews (Affinity Ops / Affinity Smart AI)
# SPDX-License-Identifier: Apache-2.0
#
# Reproducible test-suite counter for the OS-Cicada repository.
# Run from the repository root: bash scripts/count_tests.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

GO_SENTRY_FILES=$(find Sentry_Gateway -name "*_test.go" | wc -l | tr -d ' ')
GO_SENTRY_TESTS=$(grep -rn "^func Test" Sentry_Gateway | wc -l | tr -d ' ')
GO_SENTRY_SUBTESTS=$(grep -rn "t\.Run(" Sentry_Gateway | wc -l | tr -d ' ')
GO_SENTRY_BENCH=$(grep -rn "^func Benchmark" Sentry_Gateway | wc -l | tr -d ' ')
GO_CORPUS_CASES=$(grep -c '"id":' Sentry_Gateway/tests/adversarial/corpus.json | tr -d ' ')

GO_OTHER_FILES=$(find Shadow_Sandbox Mesh_Directory Licensing_Authority -name "*_test.go" | wc -l | tr -d ' ')
GO_OTHER_TESTS=$(grep -rn "^func Test" Shadow_Sandbox Mesh_Directory Licensing_Authority | wc -l | tr -d ' ')

PHP_FILES=$(find Core_API/tests -name "*Test.php" | wc -l | tr -d ' ')
PHP_TESTS=$(grep -rn "public function test" Core_API/tests | wc -l | tr -d ' ')

PY_FILES=$(find Cicada_SDK/python/tests Verification_Swarm Saga_Executor -maxdepth 2 -name "test_*.py" | wc -l | tr -d ' ')
PY_TESTS=$(grep -rn -E "^[[:space:]]*(async[[:space:]]+)?def test_" Cicada_SDK/python/tests Verification_Swarm Saga_Executor | wc -l | tr -d ' ')

TS_JS_FILES=$(find Developer_Portal/src dashboard/src Cicada_SDK/node/src -type f \( -name "*.test.ts" -o -name "*.test.tsx" -o -name "*.test.js" \) | wc -l | tr -d ' ')
TS_JS_TESTS=$(grep -rn -E "^[[:space:]]*(it|test)\(" Developer_Portal/src dashboard/src Cicada_SDK/node/src | wc -l | tr -d ' ')

DART_FILES=$(find Ciba_Flutter_App/test -name "*_test.dart" | wc -l | tr -d ' ')
DART_TESTS=$(grep -rn -E "^[[:space:]]*(test|testWidgets)\(" Ciba_Flutter_App/test | wc -l | tr -d ' ')

TOTAL_FILES=$((GO_SENTRY_FILES + GO_OTHER_FILES + PHP_FILES + PY_FILES + TS_JS_FILES + DART_FILES))
TOTAL_TOP_LEVEL=$((GO_SENTRY_TESTS + GO_OTHER_TESTS + PHP_TESTS + PY_TESTS + TS_JS_TESTS + DART_TESTS))

cat <<EOF
====================================================================
OS-Cicada Reproducible Test Suite Summary
====================================================================
Go (Sentry_Gateway)                 : ${GO_SENTRY_TESTS} top-level tests (${GO_SENTRY_FILES} files, +${GO_SENTRY_SUBTESTS} t.Run calls, ${GO_CORPUS_CASES} adversarial corpus cases, ${GO_SENTRY_BENCH} benchmarks)
Go (Shadow_Sandbox, Mesh, Licensing): ${GO_OTHER_TESTS} top-level tests (${GO_OTHER_FILES} files)
PHP (Core_API/tests)                : ${PHP_TESTS} test methods (${PHP_FILES} files)
Python (Cicada_SDK, Swarm, Saga)    : ${PY_TESTS} test functions (${PY_FILES} files)
TS/JS (Developer_Portal, dashboard, Cicada_SDK/node): ${TS_JS_TESTS} test blocks (${TS_JS_FILES} files)
Dart (Ciba_Flutter_App/test)        : ${DART_TESTS} test/testWidgets blocks (${DART_FILES} files)
--------------------------------------------------------------------
Total Test Files                    : ${TOTAL_FILES}
Total Top-Level Test Definitions    : ${TOTAL_TOP_LEVEL}
====================================================================
EOF
