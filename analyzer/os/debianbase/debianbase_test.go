package debianbase

import (
	"reflect"
	"testing"

	"golang.org/x/xerrors"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/analyzer/os"
)

func TestAnalyze(t *testing.T) {
	var tests = map[string]struct {
		path    string
		os      analyzer.OS
		wantErr error
	}{
		"Debian9": {
			path: "./testdata/debian_9",
			os:   analyzer.OS{Family: "debian", Name: "9.8"},
		},
		"DebianSid": {
			path: "./testdata/debian_sid",
			os:   analyzer.OS{Family: "debian", Name: "buster/sid"},
		},
		"Ubuntu18": {
			path: "./testdata/ubuntu_18",
			os:   analyzer.OS{Family: "ubuntu", Name: "18.04"},
		},
		"Invalid": {
			path:    "./testdata/not_debianbase",
			wantErr: os.AnalyzeOSError,
		},
	}
	a := debianbaseOSAnalyzer{}
	for i, v := range tests {
		fileMap, err := os.GetFileMap(v.path)
		if err != nil {
			t.Errorf("%s : catch the error : %v", i, err)
		}
		osInfo, err := a.Analyze(fileMap)
		if v.wantErr != nil {
			if err == nil {
				t.Errorf("%s : expected error but no error", i)
			}
			if !xerrors.Is(err, v.wantErr) {
				t.Errorf("[%s]\nexpected : %v\nactual : %v", i, v.wantErr, err)
			}
		}
		if !reflect.DeepEqual(v.os, osInfo) {
			t.Errorf("[%s]\nexpected : %v\nactual : %v", i, v.os, osInfo)
		}
	}
}
