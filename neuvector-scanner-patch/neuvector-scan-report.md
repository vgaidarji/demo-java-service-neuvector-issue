# NeuVector Scanner Report - demo-java-service

**Image:** `localhost/demo-java-service:latest`
**Base OS:** ubuntu:24.04
**Scanner:** NeuVector Scanner v4.069
**Scan date:** 2026-02-12
**Scan command:**
```
podman run --rm \
  -v /run/podman/podman.sock:/var/run/docker.sock \
  -v $(pwd):/results \
  --security-opt label=disable \
  neuvector/scanner:latest \
  -i localhost/demo-java-service:latest
```

---

## Summary

| Category | Count |
|---|---|
| Total vulnerabilities reported | 63 |
| HIGH | 24 |
| MEDIUM | 23 |
| LOW | 16 |
| OS-level (legitimate) | 52 |
| JAR-level (false positives) | **11** |

---

## Project Dependencies (from pom.xml)

| Dependency | GroupId | Version | Scope |
|---|---|---|---|
| spring-boot-starter-actuator | org.springframework.boot | 4.0.2 (parent) | compile |
| spring-boot-starter-flyway | org.springframework.boot | 4.0.2 (parent) | compile |
| spring-boot-starter-opentelemetry | org.springframework.boot | 4.0.2 (parent) | compile |
| spring-boot-starter-webmvc | org.springframework.boot | 4.0.2 (parent) | compile |
| spring-cloud-starter | org.springframework.cloud | 2025.1.0 (BOM) | compile |
| lombok | org.projectlombok | (managed) | optional |
| opentelemetry-bom | io.opentelemetry | 1.59.0 | BOM (import) |
| opentelemetry-instrumentation-bom | io.opentelemetry.instrumentation | 2.24.0 | BOM (import) |
| spring-cloud-dependencies | org.springframework.cloud | 2025.1.0 | BOM (import) |

---

## OS-Level Vulnerabilities (Legitimate)

These are real vulnerabilities in the base OS packages (ubuntu:24.04).

| Package | CVE | Severity | Version |
|---|---|---|---|
| coreutils | CVE-2016-2781 | Medium | 9.4-3ubuntu6.1 |
| curl | CVE-2025-9086 | High | 8.5.0-2ubuntu10.6 |
| curl | CVE-2025-0167 | Low | 8.5.0-2ubuntu10.6 |
| curl | CVE-2025-15224 | Low | 8.5.0-2ubuntu10.6 |
| curl | CVE-2025-10148 | Medium | 8.5.0-2ubuntu10.6 |
| curl | CVE-2025-14524 | Medium | 8.5.0-2ubuntu10.6 |
| curl | CVE-2025-14819 | Medium | 8.5.0-2ubuntu10.6 |
| curl | CVE-2025-15079 | Medium | 8.5.0-2ubuntu10.6 |
| curl/libcurl4t64 | CVE-2025-9086 | High | 8.5.0-2ubuntu10.6 |
| curl/libcurl4t64 | CVE-2025-0167 | Low | 8.5.0-2ubuntu10.6 |
| curl/libcurl4t64 | CVE-2025-15224 | Low | 8.5.0-2ubuntu10.6 |
| curl/libcurl4t64 | CVE-2025-10148 | Medium | 8.5.0-2ubuntu10.6 |
| curl/libcurl4t64 | CVE-2025-14524 | Medium | 8.5.0-2ubuntu10.6 |
| curl/libcurl4t64 | CVE-2025-14819 | Medium | 8.5.0-2ubuntu10.6 |
| curl/libcurl4t64 | CVE-2025-15079 | Medium | 8.5.0-2ubuntu10.6 |
| expat/libexpat1 | CVE-2025-66382 | Low | 2.6.1-2ubuntu0.3 |
| gnupg2/dirmngr | CVE-2026-24882 | High | 2.4.4-2ubuntu17.4 |
| gnupg2/dirmngr | CVE-2022-3219 | Low | 2.4.4-2ubuntu17.4 |
| gnupg2/dirmngr | CVE-2025-68972 | Medium | 2.4.4-2ubuntu17.4 |
| gnupg2/gnupg | CVE-2026-24882 | High | 2.4.4-2ubuntu17.4 |
| gnupg2/gnupg | CVE-2022-3219 | Low | 2.4.4-2ubuntu17.4 |
| gnupg2/gnupg | CVE-2025-68972 | Medium | 2.4.4-2ubuntu17.4 |
| gnupg2/gnupg-utils | CVE-2026-24882 | High | 2.4.4-2ubuntu17.4 |
| gnupg2/gnupg-utils | CVE-2022-3219 | Low | 2.4.4-2ubuntu17.4 |
| gnupg2/gnupg-utils | CVE-2025-68972 | Medium | 2.4.4-2ubuntu17.4 |
| gnupg2/gpg | CVE-2026-24882 | High | 2.4.4-2ubuntu17.4 |
| gnupg2/gpg | CVE-2022-3219 | Low | 2.4.4-2ubuntu17.4 |
| gnupg2/gpg | CVE-2025-68972 | Medium | 2.4.4-2ubuntu17.4 |
| gnupg2/gpg-agent | CVE-2026-24882 | High | 2.4.4-2ubuntu17.4 |
| gnupg2/gpg-agent | CVE-2022-3219 | Low | 2.4.4-2ubuntu17.4 |
| gnupg2/gpg-agent | CVE-2025-68972 | Medium | 2.4.4-2ubuntu17.4 |
| gnupg2/gpgconf | CVE-2026-24882 | High | 2.4.4-2ubuntu17.4 |
| gnupg2/gpgconf | CVE-2022-3219 | Low | 2.4.4-2ubuntu17.4 |
| gnupg2/gpgconf | CVE-2025-68972 | Medium | 2.4.4-2ubuntu17.4 |
| gnupg2/gpgsm | CVE-2026-24882 | High | 2.4.4-2ubuntu17.4 |
| gnupg2/gpgsm | CVE-2022-3219 | Low | 2.4.4-2ubuntu17.4 |
| gnupg2/gpgsm | CVE-2025-68972 | Medium | 2.4.4-2ubuntu17.4 |
| gnupg2/gpgv | CVE-2026-24882 | High | 2.4.4-2ubuntu17.4 |
| gnupg2/gpgv | CVE-2022-3219 | Low | 2.4.4-2ubuntu17.4 |
| gnupg2/gpgv | CVE-2025-68972 | Medium | 2.4.4-2ubuntu17.4 |
| gnupg2/keyboxd | CVE-2026-24882 | High | 2.4.4-2ubuntu17.4 |
| gnupg2/keyboxd | CVE-2022-3219 | Low | 2.4.4-2ubuntu17.4 |
| gnupg2/keyboxd | CVE-2025-68972 | Medium | 2.4.4-2ubuntu17.4 |
| libgcrypt20 | CVE-2024-2236 | Medium | 1.10.3-2build1 |
| pam/libpam-modules | CVE-2025-8941 | High | 1.5.3-5ubuntu5.5 |
| pam/libpam-modules-bin | CVE-2025-8941 | High | 1.5.3-5ubuntu5.5 |
| pam/libpam-runtime | CVE-2025-8941 | High | 1.5.3-5ubuntu5.5 |
| pam/libpam0g | CVE-2025-8941 | High | 1.5.3-5ubuntu5.5 |
| shadow/login | CVE-2024-56433 | Low | 1:4.13+dfsg1-4ubuntu3.2 |
| shadow/passwd | CVE-2024-56433 | Low | 1:4.13+dfsg1-4ubuntu3.2 |
| tar | CVE-2025-45582 | Medium | 1.35+dfsg-3build1 |
| wget | CVE-2021-31879 | Medium | 1.21.4-1ubuntu4.1 |

---

## JAR-Level Vulnerabilities (ALL FALSE POSITIVES)

  False Positive Breakdown
  ┌─────────────┬──────────────────────┬─────────────────────────────────────────────┬────────────────────────────────────┐
  │ Scanner key │     Flagged JARs     │                 Wrong CVEs                  │          Actually affects          │
  ├─────────────┼──────────────────────┼─────────────────────────────────────────────┼────────────────────────────────────┤
  │ jar:common  │ 4 OpenTelemetry JARs │ CVE-2024-46985, CVE-2024-46997 (8 findings) │ DataEase (data visualization tool) │
  ├─────────────┼──────────────────────┼─────────────────────────────────────────────┼────────────────────────────────────┤
  │ jar:okhttp  │ 1 OpenTelemetry JAR  │ CVE-2021-0341, CVE-2016-2402 (2 findings)   │ OkHttp (not this JAR)              │
  ├─────────────┼──────────────────────┼─────────────────────────────────────────────┼────────────────────────────────────┤
  │ jar:metrics │ 1 OpenTelemetry JAR  │ CVE-2022-20621 (1 finding)                  │ Jenkins Metrics Plugin             │
  └─────────────┴──────────────────────┴─────────────────────────────────────────────┴────────────────────────────────────┘

### False Positive #1: `jar:common` -- 4 JARs flagged

| Flagged JAR file | Actual library | Scanner identified as |
|---|---|---|
| `opentelemetry-common-1.59.0.jar` | `io.opentelemetry:opentelemetry-common` | `jar:common` |
| `opentelemetry-exporter-common-1.59.0.jar` | `io.opentelemetry:opentelemetry-exporter-common` | `jar:common` |
| `opentelemetry-exporter-otlp-common-1.59.0.jar` | `io.opentelemetry:opentelemetry-exporter-otlp-common` | `jar:common` |
| `opentelemetry-sdk-common-1.59.0.jar` | `io.opentelemetry:opentelemetry-sdk-common` | `jar:common` |

**CVEs incorrectly matched:**

| CVE | Severity | Actually affects | Description |
|---|---|---|---|
| CVE-2024-46985 | High | **DataEase** (data visualization tool) | XXE injection in static resource upload interface. Fixed in DataEase v2.10.1 |
| CVE-2024-46997 | High | **DataEase** (data visualization tool) | RCE via H2 JDBC connection parameter injection. Fixed in DataEase v2.10.1 |

**Why it's false:** These OpenTelemetry JARs lack `pom.properties`. The scanner falls back to MANIFEST.MF, extracts the generic `Implementation-Title` "common", defaults the vendor to "jar", producing the lookup key `jar:common`. This collides with the CVE database shortcut key `jar:common` generated from a completely unrelated DataEase artifact.

---

### False Positive #2: `jar:okhttp` -- 1 JAR flagged

| Flagged JAR file | Actual library | Scanner identified as |
|---|---|---|
| `opentelemetry-exporter-sender-okhttp-1.59.0.jar` | `io.opentelemetry:opentelemetry-exporter-sender-okhttp` | `jar:okhttp` |

**CVEs incorrectly matched:**

| CVE | Severity | Actually affects | Description |
|---|---|---|---|
| CVE-2021-0341 | High | **OkHttp** (`com.squareup.okhttp3:okhttp` < 4.9.2) | Improper hostname verification allowing MitM attacks |
| CVE-2016-2402 | Medium | **OkHttp** (`com.squareup.okhttp3:okhttp` < 2.7.4/3.1.2) | Certificate pinning bypass |

**Why it's false:** The flagged JAR is an OpenTelemetry exporter module that _uses_ OkHttp as a transport -- it is NOT OkHttp itself. The scanner extracted "okhttp" from MANIFEST.MF `Implementation-Title`, defaulted vendor to "jar", and matched `jar:okhttp` against OkHttp CVEs. The actual OkHttp library in the image (if present) would be a separate JAR with its own `pom.properties`.

---

### False Positive #3: `jar:metrics` -- 1 JAR flagged

| Flagged JAR file | Actual library | Scanner identified as |
|---|---|---|
| `opentelemetry-sdk-metrics-1.59.0.jar` | `io.opentelemetry:opentelemetry-sdk-metrics` | `jar:metrics` |

**CVEs incorrectly matched:**

| CVE | Severity | Actually affects | Description |
|---|---|---|---|
| CVE-2022-20621 | Medium | **Jenkins Metrics Plugin** (`org.jenkins-ci.plugins:metrics` < 4.0.2.8.1) | Credential stored unencrypted in Jenkins config file |

**Why it's false:** This is the OpenTelemetry SDK metrics module. There is no Jenkins installation in this image. The scanner extracted "metrics" from MANIFEST.MF, defaulted vendor to "jar", and `jar:metrics` collided with the shortcut key for the Jenkins Metrics Plugin CVE.

---

## Root Cause Analysis

The false positives are caused by a **bug in the NeuVector scanner** involving two code paths:

### 1. JAR identification (`share/scan/apps.go` -> `parseJarPackage()`)

OpenTelemetry JARs do not include `pom.properties` inside the JAR archive. When `pom.properties` is absent, the scanner falls back to parsing `META-INF/MANIFEST.MF`. The MANIFEST.MF lacks `Implementation-Vendor-Id`, so the vendor defaults to `"jar"`. The `Implementation-Title` or `Bundle-Name` contains generic words like `common`, `okhttp`, `metrics`. This produces module identifiers like `jar:common`, `jar:okhttp`, `jar:metrics`.

### 2. CVE database indexing (`common/db.go` -> `LoadAppVulsTb()`)

For every CVE entry (e.g., `com.squareup.okhttp3:okhttp`), three lookup keys are generated:
- `com.squareup.okhttp3:okhttp` -- correct, matches `pom.properties`
- `com.squareup.okhttp3.okhttp` -- dot-separated, legacy compat
- **`jar:okhttp`** -- shortcut key (THIS CAUSES THE COLLISION)

The `jar:<artifactId>` shortcut key is overly broad and collides with the MANIFEST.MF fallback vendor prefix `jar:`, causing unrelated JARs to match CVEs for completely different products.

### Collision diagram

```
CVE Database                           JAR in Image
──────────                             ────────────
com.squareup.okhttp3:okhttp            opentelemetry-exporter-sender-okhttp-1.59.0.jar
  -> key: "jar:okhttp" (shortcut)        -> identified as: "jar:okhttp" (MANIFEST.MF fallback)
                    \                      /
                     └──── COLLISION! ────┘
                     Scanner matches CVE
                     to wrong library
```

---

## Appendix: Complete JAR Dependency List

JARs found inside `app/app.jar:BOOT-INF/lib/` (from Spring Boot fat JAR):

| JAR filename | Metadata source | Scanner identifier |
|---|---|---|
| opentelemetry-api-1.59.0.jar | MANIFEST.MF (no vendor) | `jar:all` |
| opentelemetry-api-incubator-1.59.0-alpha.jar | MANIFEST.MF (no vendor) | `jar:incubator` |
| opentelemetry-common-1.59.0.jar | MANIFEST.MF (no vendor) | `jar:common` **[FP]** |
| opentelemetry-context-1.59.0.jar | MANIFEST.MF (no vendor) | `jar:context` |
| opentelemetry-exporter-common-1.59.0.jar | MANIFEST.MF (no vendor) | `jar:common` **[FP]** |
| opentelemetry-exporter-logging-1.59.0.jar | MANIFEST.MF (no vendor) | `jar:logging` |
| opentelemetry-exporter-otlp-1.59.0.jar | MANIFEST.MF (no vendor) | `jar:all` |
| opentelemetry-exporter-otlp-common-1.59.0.jar | MANIFEST.MF (no vendor) | `jar:common` **[FP]** |
| opentelemetry-exporter-sender-okhttp-1.59.0.jar | MANIFEST.MF (no vendor) | `jar:okhttp` **[FP]** |
| opentelemetry-extension-trace-propagators-1.59.0.jar | MANIFEST.MF (no vendor) | `jar:trace-propagators` |
| opentelemetry-sdk-1.59.0.jar | MANIFEST.MF (no vendor) | `jar:all` |
| opentelemetry-sdk-common-1.59.0.jar | MANIFEST.MF (no vendor) | `jar:common` **[FP]** |
| opentelemetry-sdk-extension-autoconfigure-1.59.0.jar | MANIFEST.MF (no vendor) | `jar:autoconfigure` |
| opentelemetry-sdk-extension-autoconfigure-spi-1.59.0.jar | MANIFEST.MF (no vendor) | `jar:autoconfigure-spi` |
| opentelemetry-sdk-logs-1.59.0.jar | MANIFEST.MF (no vendor) | `jar:logs` |
| opentelemetry-sdk-metrics-1.59.0.jar | MANIFEST.MF (no vendor) | `jar:metrics` **[FP]** |
| opentelemetry-sdk-trace-1.59.0.jar | pom.properties (wrong: jctools-core) | `org.jctools:jctools-core` |
| opentelemetry-semconv-1.37.0.jar | MANIFEST.MF (no vendor) | `jar:opentelemetry-semconv` |
| spring-boot-4.0.2.jar | MANIFEST.MF (no vendor) | `jar:Spring Boot` |
| spring-boot-actuator-4.0.2.jar | MANIFEST.MF (no vendor) | `jar:Spring Boot Actuator` |
| spring-boot-actuator-autoconfigure-4.0.2.jar | MANIFEST.MF (no vendor) | `jar:Spring Boot Actuator AutoConfigure` |
| spring-boot-autoconfigure-4.0.2.jar | MANIFEST.MF (no vendor) | `jar:Spring Boot AutoConfigure` |
| spring-aop-*.jar | MANIFEST.MF (no vendor) | `jar:spring-aop` |
| spring-beans-*.jar | MANIFEST.MF (no vendor) | `jar:spring-beans` |
| spring-context-*.jar | MANIFEST.MF (no vendor) | `jar:spring-context` |
| spring-core-*.jar | MANIFEST.MF (no vendor) | `jar:spring-core` |
| spring-expression-*.jar | MANIFEST.MF (no vendor) | `jar:spring-expression` |
| spring-jcl-*.jar | MANIFEST.MF (no vendor) | `jar:spring-jcl` |
| spring-web-*.jar | MANIFEST.MF (no vendor) | `jar:spring-web` |
| spring-webmvc-*.jar | MANIFEST.MF (no vendor) | `jar:spring-webmvc` |
| jackson-annotations-*.jar | pom.properties | `com.fasterxml.jackson.core:jackson-annotations` |
| jackson-core-*.jar | pom.properties | `com.fasterxml.jackson.core:jackson-core` |
| jackson-databind-*.jar | pom.properties | `com.fasterxml.jackson.core:jackson-databind` |
| logback-classic-*.jar | pom.properties | `ch.qos.logback:logback-classic` |
| logback-core-*.jar | pom.properties | `ch.qos.logback:logback-core` |
| micrometer-commons-*.jar | MANIFEST.MF Bundle-SymbolicName | `micrometer-commons` |
| micrometer-core-*.jar | MANIFEST.MF Bundle-SymbolicName | `micrometer-core` |
| micrometer-observation-*.jar | MANIFEST.MF Bundle-SymbolicName | `micrometer-observation` |
| snakeyaml-*.jar | pom.properties | `org.yaml:snakeyaml` |
| slf4j-api-*.jar | pom.properties | `org.slf4j:slf4j-api` |
| tomcat-embed-core-*.jar | MANIFEST.MF Bundle-SymbolicName | `org.apache.tomcat-embed-core` |
| tomcat-embed-el-*.jar | MANIFEST.MF Bundle-SymbolicName | `org.apache.tomcat-embed-jasper-el` |
| tomcat-embed-websocket-*.jar | MANIFEST.MF Bundle-SymbolicName | `org.apache.tomcat-embed-websocket` |
| flyway-core-*.jar | pom.properties | `org.flywaydb:flyway-core` |
| log4j-api-*.jar | pom.properties | `org.apache.logging.log4j:log4j-api` |
| log4j-to-slf4j-*.jar | pom.properties | `org.apache.logging.log4j:log4j-to-slf4j` |

---

## Conclusion

**11 out of 63 reported vulnerabilities are false positives** (17%), all caused by the NeuVector scanner's `jar:<artifactId>` shortcut key mechanism colliding with MANIFEST.MF fallback parsing. All 6 false-positive JARs are OpenTelemetry libraries that lack `pom.properties`.

The false positives inflate the HIGH severity count: **5 of the 24 HIGH findings are false** (CVE-2024-46985 x4, CVE-2024-46997 x4, CVE-2021-0341 x1 = 9 findings across 5 JARs reported as HIGH, but should be 0).
