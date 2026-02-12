// Add these tests to cvetools/apps_test.go in the neuvector/scanner repository.
// They verify end-to-end that the jar: shortcut key removal prevents false
// positive CVE matches while preserving legitimate matches.

package cvetools

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/neuvector/scanner/common"
	"github.com/neuvector/scanner/detectors"
)

// writeAppsTb creates a temporary apps.tb file with the given entries.
func writeAppsTb(t *testing.T, entries []common.AppModuleVul) string {
	t.Helper()
	dir := t.TempDir()
	var buf bytes.Buffer
	for _, e := range entries {
		data, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("failed to marshal entry: %v", err)
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}
	err := os.WriteFile(filepath.Join(dir, "apps.tb"), buf.Bytes(), 0644)
	if err != nil {
		t.Fatalf("failed to write apps.tb: %v", err)
	}
	return dir
}

// TestDetectAppVul_NoFalsePositiveJarOkhttp verifies that jar:okhttp
// (from an OpenTelemetry JAR's MANIFEST.MF fallback) does NOT match
// CVEs for com.squareup.okhttp3:okhttp.
func TestDetectAppVul_NoFalsePositiveJarOkhttp(t *testing.T) {
	dir := writeAppsTb(t, []common.AppModuleVul{
		{
			VulName:     "CVE-2021-0341",
			AppName:     "jar",
			ModuleName:  "com.squareup.okhttp3:okhttp",
			Description: "OkHttp hostname verification bypass",
			Severity:    "High",
			AffectedVer: []common.AppModuleVersion{{OpCode: "lt", Version: "4.9.3"}},
			FixedVer:    []common.AppModuleVersion{{OpCode: "gteq", Version: "4.9.3"}},
		},
	})

	// Simulate what the scanner produces for opentelemetry-exporter-sender-okhttp-1.58.0.jar
	// which lacks pom.properties -- MANIFEST.MF fallback produces jar:okhttp
	apps := []detectors.AppFeatureVersion{
		{
			AppName:    "jar",
			ModuleName: "jar:okhttp",
			Version:    "1.58.0",
			FileName:   "app/libs/opentelemetry-exporter-sender-okhttp-1.58.0.jar",
		},
	}

	cv := &ScanTools{}
	vuls := cv.DetectAppVul(dir, apps, "")

	if len(vuls) != 0 {
		t.Errorf("expected 0 vulnerabilities for jar:okhttp (false positive), got %d", len(vuls))
		for _, v := range vuls {
			t.Errorf("  false positive: %s matched against %s", v.Vf.Name, v.Ft.File)
		}
	}
}

// TestDetectAppVul_NoFalsePositiveJarLibrary verifies that jar:library
// (from OpenTelemetry instrumentation JARs) does NOT match CVEs for
// Jenkins FindBugs Plugin.
func TestDetectAppVul_NoFalsePositiveJarLibrary(t *testing.T) {
	dir := writeAppsTb(t, []common.AppModuleVul{
		{
			VulName:     "CVE-2018-1000011",
			AppName:     "jar",
			ModuleName:  "org.jvnet.hudson.plugins:findbugs:library",
			Description: "Jenkins FindBugs Plugin XXE",
			Severity:    "High",
			AffectedVer: []common.AppModuleVersion{{OpCode: "lt", Version: "4.72"}},
		},
	})

	// OpenTelemetry instrumentation JARs produce jar:library from MANIFEST.MF
	apps := []detectors.AppFeatureVersion{
		{
			AppName:    "jar",
			ModuleName: "jar:library",
			Version:    "2.23.0-alpha",
			FileName:   "app/libs/opentelemetry-jdbc-2.23.0-alpha.jar",
		},
		{
			AppName:    "jar",
			ModuleName: "jar:library",
			Version:    "2.23.0-alpha",
			FileName:   "app/libs/opentelemetry-kafka-clients-2.6-2.23.0-alpha.jar",
		},
	}

	cv := &ScanTools{}
	vuls := cv.DetectAppVul(dir, apps, "")

	if len(vuls) != 0 {
		t.Errorf("expected 0 vulnerabilities for jar:library (false positive), got %d", len(vuls))
		for _, v := range vuls {
			t.Errorf("  false positive: %s matched against %s", v.Vf.Name, v.Ft.File)
		}
	}
}

// TestDetectAppVul_NoFalsePositiveJarMetrics verifies that jar:metrics
// (from OpenTelemetry SDK) does NOT match CVEs for Jenkins Metrics Plugin.
func TestDetectAppVul_NoFalsePositiveJarMetrics(t *testing.T) {
	dir := writeAppsTb(t, []common.AppModuleVul{
		{
			VulName:     "CVE-2022-20621",
			AppName:     "jar",
			ModuleName:  "org.jenkins-ci.plugins:metrics",
			Description: "Jenkins Metrics Plugin plain text storage",
			Severity:    "Medium",
			AffectedVer: []common.AppModuleVersion{{OpCode: "lt", Version: "4.2.0"}},
		},
	})

	apps := []detectors.AppFeatureVersion{
		{
			AppName:    "jar",
			ModuleName: "jar:metrics",
			Version:    "1.58.0",
			FileName:   "app/libs/opentelemetry-sdk-metrics-1.58.0.jar",
		},
	}

	cv := &ScanTools{}
	vuls := cv.DetectAppVul(dir, apps, "")

	if len(vuls) != 0 {
		t.Errorf("expected 0 vulnerabilities for jar:metrics (false positive), got %d", len(vuls))
	}
}

// TestDetectAppVul_NoFalsePositiveJarCommon verifies that jar:common
// does NOT match unrelated CVEs.
func TestDetectAppVul_NoFalsePositiveJarCommon(t *testing.T) {
	dir := writeAppsTb(t, []common.AppModuleVul{
		{
			VulName:     "CVE-2024-46985",
			AppName:     "jar",
			ModuleName:  "org.example:common",
			Description: "Some common library vulnerability",
			Severity:    "High",
			AffectedVer: []common.AppModuleVersion{{OpCode: "lt", Version: "2.10.1"}},
		},
	})

	apps := []detectors.AppFeatureVersion{
		{
			AppName:    "jar",
			ModuleName: "jar:common",
			Version:    "1.58.0",
			FileName:   "app/libs/opentelemetry-common-1.58.0.jar",
		},
	}

	cv := &ScanTools{}
	vuls := cv.DetectAppVul(dir, apps, "")

	if len(vuls) != 0 {
		t.Errorf("expected 0 vulnerabilities for jar:common (false positive), got %d", len(vuls))
	}
}

// TestDetectAppVul_LegitimateExactMatch verifies that exact groupId:artifactId
// matches (from JARs with pom.properties) still work correctly.
func TestDetectAppVul_LegitimateExactMatch(t *testing.T) {
	dir := writeAppsTb(t, []common.AppModuleVul{
		{
			VulName:     "CVE-2021-0341",
			AppName:     "jar",
			ModuleName:  "com.squareup.okhttp3:okhttp",
			Description: "OkHttp hostname verification bypass",
			Severity:    "High",
			AffectedVer: []common.AppModuleVersion{{OpCode: "lt", Version: "4.9.3"}},
			FixedVer:    []common.AppModuleVersion{{OpCode: "gteq", Version: "4.9.3"}},
		},
	})

	// JAR with pom.properties produces exact groupId:artifactId
	apps := []detectors.AppFeatureVersion{
		{
			AppName:    "jar",
			ModuleName: "com.squareup.okhttp3:okhttp",
			Version:    "4.9.1", // vulnerable version
			FileName:   "app/libs/okhttp-4.9.1.jar",
		},
	}

	cv := &ScanTools{}
	vuls := cv.DetectAppVul(dir, apps, "")

	if len(vuls) != 1 {
		t.Fatalf("expected 1 vulnerability for exact match, got %d", len(vuls))
	}
	if vuls[0].Vf.Name != "CVE-2021-0341" {
		t.Errorf("expected CVE-2021-0341, got %s", vuls[0].Vf.Name)
	}
}

// TestDetectAppVul_LegitimateDotSeparatedMatch verifies that dot-separated
// module names (backward compat) still match correctly.
func TestDetectAppVul_LegitimateDotSeparatedMatch(t *testing.T) {
	dir := writeAppsTb(t, []common.AppModuleVul{
		{
			VulName:     "CVE-2021-0341",
			AppName:     "jar",
			ModuleName:  "com.squareup.okhttp3:okhttp",
			Description: "OkHttp hostname verification bypass",
			Severity:    "High",
			AffectedVer: []common.AppModuleVersion{{OpCode: "lt", Version: "4.9.3"}},
			FixedVer:    []common.AppModuleVersion{{OpCode: "gteq", Version: "4.9.3"}},
		},
	})

	// Some older scanners produce dot-separated module names
	apps := []detectors.AppFeatureVersion{
		{
			AppName:    "jar",
			ModuleName: "com.squareup.okhttp3.okhttp",
			Version:    "4.9.1",
			FileName:   "app/libs/okhttp-4.9.1.jar",
		},
	}

	cv := &ScanTools{}
	vuls := cv.DetectAppVul(dir, apps, "")

	if len(vuls) != 1 {
		t.Fatalf("expected 1 vulnerability for dot-separated match, got %d", len(vuls))
	}
	if vuls[0].Vf.Name != "CVE-2021-0341" {
		t.Errorf("expected CVE-2021-0341, got %s", vuls[0].Vf.Name)
	}
}

// TestDetectAppVul_FixedVersionNotReported verifies that a JAR at a fixed
// version is NOT reported as vulnerable.
func TestDetectAppVul_FixedVersionNotReported(t *testing.T) {
	dir := writeAppsTb(t, []common.AppModuleVul{
		{
			VulName:     "CVE-2021-0341",
			AppName:     "jar",
			ModuleName:  "com.squareup.okhttp3:okhttp",
			Description: "OkHttp hostname verification bypass",
			Severity:    "High",
			AffectedVer: []common.AppModuleVersion{{OpCode: "lt", Version: "4.9.3"}},
		},
	})

	apps := []detectors.AppFeatureVersion{
		{
			AppName:    "jar",
			ModuleName: "com.squareup.okhttp3:okhttp",
			Version:    "5.3.1", // well past fixed version
			FileName:   "app/libs/okhttp-jvm-5.3.1.jar",
		},
	}

	cv := &ScanTools{}
	vuls := cv.DetectAppVul(dir, apps, "")

	if len(vuls) != 0 {
		t.Errorf("expected 0 vulnerabilities for fixed version 5.3.1, got %d", len(vuls))
	}
}
