# NeuVector Scanner Patch: Fix jar: Shortcut Key False Positives

## Problem

`LoadAppVulsTb()` in `common/db.go` generates a `jar:<artifactId>` shortcut
key for every CVE entry. For example, `com.squareup.okhttp3:okhttp` produces
`jar:okhttp`. JARs without `pom.properties` (e.g., OpenTelemetry) have their
MANIFEST.MF fallback produce generic module names like `jar:okhttp`,
`jar:library`, `jar:metrics`, `jar:common` -- which collide with these
shortcut keys, causing false positive CVE matches.

## Fix

Remove the `jar:<artifactId>` shortcut key generation (7 lines) from
`LoadAppVulsTb()`. Original and dot-separated keys are preserved.

## Files

| File | Description |
|---|---|
| `fix-jar-shortcut-false-positives.patch` | Git-style patch diff |
| `db_patched.go` | Complete patched `LoadAppVulsTb()` function |
| `db_jar_shortcut_test.go` | Unit tests for `common/db_test.go` |
| `apps_false_positive_test.go` | Integration tests for `cvetools/apps_test.go` |

## Safety Analysis

| JAR type | Match mechanism | Affected? |
|---|---|---|
| JAR with pom.properties | `groupId:artifactId` key | No |
| JAR with MANIFEST.MF + vendor | `vendorId:title` or dot-separated | No |
| JAR with vendor=`jar` fallback | Was `jar:` shortcut (REMOVED) | Yes -- prevents false positives |
| log4j | Dedicated handling in DetectAppVul() | No |

## Root Cause Details

# NeuVector Scan Report - False Positive Analysis

See [neuvector-scan-report](./neuvector-scan-report.md).
