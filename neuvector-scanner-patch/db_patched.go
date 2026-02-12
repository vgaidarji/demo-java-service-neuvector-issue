// This file contains the patched LoadAppVulsTb() function for common/db.go
// in the neuvector/scanner repository.
//
// CHANGE: Removed jar:<artifactId> shortcut key generation that caused
// false positive CVE matches when JARs without pom.properties (e.g.,
// OpenTelemetry) produced generic module names like jar:okhttp, jar:library.
//
// Apply this by replacing the LoadAppVulsTb() function in common/db.go.

package common

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

func LoadAppVulsTb(path string) (map[string][]AppModuleVul, error) {
	filename := fmt.Sprintf("%s/apps.tb", path)
	fvul, err := os.Open(filename)
	if err != nil {
		log.WithFields(log.Fields{"filename": filename, "error": err}).Error("open file error")
		return nil, err
	}
	defer fvul.Close()

	data, err := io.ReadAll(fvul)
	if err != nil {
		log.WithFields(log.Fields{"filename": filename, "error": err}).Error("Read file error")
		return nil, err
	}

	vul := make(map[string][]AppModuleVul, 0)

	buf := make([]byte, maxBufferSize)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(buf, maxBufferSize)
	for scanner.Scan() {
		var v AppModuleVul
		s := scanner.Text()
		err := json.Unmarshal([]byte(s), &v)
		if err == nil {
			vf, ok := vul[v.ModuleName]
			if !ok {
				vf = make([]AppModuleVul, 0)
			}
			vf = append(vf, v)
			vul[v.ModuleName] = vf
		} else {
			log.Error("Unmarshal vulnerability err")
		}
	}

	// for org.apache.logging.log4j:log4j-core, we will also search
	// org.apache.logging.log4j.log4j-core: for backward compatibility
	// NOTE: The previous jar:<artifactId> shortcut key was removed because it
	// caused false positive collisions with unrelated modules (e.g., jar:okhttp
	// from OpenTelemetry matched against com.squareup.okhttp3:okhttp CVEs).
	var mns []string
	for mn := range vul {
		if colon := strings.LastIndex(mn, ":"); colon > 0 {
			mns = append(mns, mn)
		}
	}

	for _, mn := range mns {
		m := strings.ReplaceAll(mn, ":", ".")
		vf := vul[mn]

		if _, ok := vul[m]; ok {
			vul[m] = uniqueVulDb(append(vul[m], vf...))
		} else {
			vul[m] = vf
		}
	}
	return vul, nil
}
