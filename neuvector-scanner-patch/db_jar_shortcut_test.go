// Add this test to common/db_test.go in the neuvector/scanner repository.
// It verifies that LoadAppVulsTb() no longer generates jar:<artifactId>
// shortcut keys that caused false positive CVE matches.

package common

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAppVulsTb_NoJarShortcutKeys(t *testing.T) {
	dir := t.TempDir()

	// Create a minimal apps.tb with CVE entries that previously generated
	// problematic jar: shortcut keys
	entries := []AppModuleVul{
		{
			VulName:     "CVE-2021-0341",
			AppName:     "jar",
			ModuleName:  "com.squareup.okhttp3:okhttp",
			Description: "OkHttp hostname verification bypass",
			Severity:    "High",
			AffectedVer: []AppModuleVersion{{OpCode: "lt", Version: "4.9.3"}},
		},
		{
			VulName:     "CVE-2022-20621",
			AppName:     "jar",
			ModuleName:  "org.jenkins-ci.plugins:metrics",
			Description: "Jenkins Metrics Plugin plain text storage",
			Severity:    "Medium",
			AffectedVer: []AppModuleVersion{{OpCode: "lt", Version: "4.2.0"}},
		},
		{
			VulName:     "CVE-2018-1000011",
			AppName:     "jar",
			ModuleName:  "org.jvnet.hudson.plugins:findbugs:library",
			Description: "Jenkins FindBugs Plugin XXE",
			Severity:    "High",
			AffectedVer: []AppModuleVersion{{OpCode: "lt", Version: "4.72"}},
		},
	}

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

	// Load the vulnerability table
	vul, err := LoadAppVulsTb(dir)
	if err != nil {
		t.Fatalf("LoadAppVulsTb failed: %v", err)
	}

	// --- Verify original groupId:artifactId keys ARE present ---

	if _, ok := vul["com.squareup.okhttp3:okhttp"]; !ok {
		t.Error("expected original key 'com.squareup.okhttp3:okhttp' to exist")
	}
	if _, ok := vul["org.jenkins-ci.plugins:metrics"]; !ok {
		t.Error("expected original key 'org.jenkins-ci.plugins:metrics' to exist")
	}
	if _, ok := vul["org.jvnet.hudson.plugins:findbugs:library"]; !ok {
		t.Error("expected original key 'org.jvnet.hudson.plugins:findbugs:library' to exist")
	}

	// --- Verify dot-separated backward-compat keys ARE present ---

	if _, ok := vul["com.squareup.okhttp3.okhttp"]; !ok {
		t.Error("expected dot-separated key 'com.squareup.okhttp3.okhttp' to exist")
	}
	if _, ok := vul["org.jenkins-ci.plugins.metrics"]; !ok {
		t.Error("expected dot-separated key 'org.jenkins-ci.plugins.metrics' to exist")
	}

	// --- Verify jar: shortcut keys are NOT present ---

	jarKeys := []string{
		"jar:okhttp",
		"jar:metrics",
		"jar:library",
		"jar:findbugs:library",
	}
	for _, key := range jarKeys {
		if _, ok := vul[key]; ok {
			t.Errorf("jar: shortcut key '%s' must NOT be generated (causes false positives)", key)
		}
	}

	// --- Verify CVE data integrity for existing keys ---

	okhttp := vul["com.squareup.okhttp3:okhttp"]
	if len(okhttp) != 1 {
		t.Errorf("expected 1 vulnerability for okhttp, got %d", len(okhttp))
	} else if okhttp[0].VulName != "CVE-2021-0341" {
		t.Errorf("expected CVE-2021-0341, got %s", okhttp[0].VulName)
	}

	// Dot-separated key should have same data
	okhttpDot := vul["com.squareup.okhttp3.okhttp"]
	if len(okhttpDot) != 1 {
		t.Errorf("expected 1 vulnerability for okhttp dot-separated, got %d", len(okhttpDot))
	} else if okhttpDot[0].VulName != "CVE-2021-0341" {
		t.Errorf("expected CVE-2021-0341 in dot-separated key, got %s", okhttpDot[0].VulName)
	}
}

func TestLoadAppVulsTb_EmptyFile(t *testing.T) {
	dir := t.TempDir()

	err := os.WriteFile(filepath.Join(dir, "apps.tb"), []byte(""), 0644)
	if err != nil {
		t.Fatalf("failed to write apps.tb: %v", err)
	}

	vul, err := LoadAppVulsTb(dir)
	if err != nil {
		t.Fatalf("LoadAppVulsTb failed on empty file: %v", err)
	}
	if len(vul) != 0 {
		t.Errorf("expected empty map for empty file, got %d entries", len(vul))
	}
}

func TestLoadAppVulsTb_NoColonModuleName(t *testing.T) {
	dir := t.TempDir()

	// Entry without colon in ModuleName should not generate any extra keys
	entry := AppModuleVul{
		VulName:     "CVE-2099-0001",
		AppName:     "npm",
		ModuleName:  "lodash",
		Description: "test",
		Severity:    "High",
		AffectedVer: []AppModuleVersion{{OpCode: "lt", Version: "4.17.21"}},
	}

	data, _ := json.Marshal(entry)
	data = append(data, '\n')
	err := os.WriteFile(filepath.Join(dir, "apps.tb"), data, 0644)
	if err != nil {
		t.Fatalf("failed to write apps.tb: %v", err)
	}

	vul, err := LoadAppVulsTb(dir)
	if err != nil {
		t.Fatalf("LoadAppVulsTb failed: %v", err)
	}

	// Only the original key should exist
	if _, ok := vul["lodash"]; !ok {
		t.Error("expected 'lodash' key to exist")
	}

	// No jar: or dot-separated key should exist
	if _, ok := vul["jar:lodash"]; ok {
		t.Error("jar:lodash should not exist for non-colon module names")
	}

	if len(vul) != 1 {
		t.Errorf("expected exactly 1 key, got %d", len(vul))
	}
}

func TestLoadAppVulsTb_MultipleVulsSameModule(t *testing.T) {
	dir := t.TempDir()

	entries := []AppModuleVul{
		{
			VulName:     "CVE-2021-0341",
			AppName:     "jar",
			ModuleName:  "com.squareup.okhttp3:okhttp",
			Severity:    "High",
			AffectedVer: []AppModuleVersion{{OpCode: "lt", Version: "4.9.3"}},
		},
		{
			VulName:     "CVE-2016-2402",
			AppName:     "jar",
			ModuleName:  "com.squareup.okhttp3:okhttp",
			Severity:    "Medium",
			AffectedVer: []AppModuleVersion{{OpCode: "lt", Version: "3.1.2"}},
		},
	}

	var buf bytes.Buffer
	for _, e := range entries {
		data, _ := json.Marshal(e)
		buf.Write(data)
		buf.WriteByte('\n')
	}
	os.WriteFile(filepath.Join(dir, "apps.tb"), buf.Bytes(), 0644)

	vul, err := LoadAppVulsTb(dir)
	if err != nil {
		t.Fatalf("LoadAppVulsTb failed: %v", err)
	}

	// Both CVEs should be under the same key
	if len(vul["com.squareup.okhttp3:okhttp"]) != 2 {
		t.Errorf("expected 2 vulnerabilities, got %d", len(vul["com.squareup.okhttp3:okhttp"]))
	}

	// Dot-separated should also have both
	if len(vul["com.squareup.okhttp3.okhttp"]) != 2 {
		t.Errorf("expected 2 vulnerabilities in dot-separated key, got %d", len(vul["com.squareup.okhttp3.okhttp"]))
	}

	// No jar: key
	if _, ok := vul["jar:okhttp"]; ok {
		t.Error("jar:okhttp must NOT exist")
	}
}
