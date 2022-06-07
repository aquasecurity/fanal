package rpm

import (
	"strings"
	"testing"

	"github.com/aquasecurity/fanal/types"
	"github.com/stretchr/testify/assert"
)

func TestParseMarinerDistrolessManifest(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantPkgs []types.Package
		wantErr  string
	}{
		{
			name: "happy path",
			content: `mariner-release	2.0-12.cm2	1653816591	1653753130	Microsoft Corporation	(none)	580	noarch	0	mariner-release-2.0-12.cm2.src.rpm
filesystem	1.1-9.cm2	1653816591	1653628924	Microsoft Corporation	(none)	7596	x86_64	0	filesystem-1.1-9.cm2.src.rpm
glibc	2.35-2.cm2	1653816591	1653628955	Microsoft Corporation	(none)	10855265	x86_64	0	glibc-2.35-2.cm2.src.rpm`,
			wantPkgs: []types.Package{
				{
					Name:    "mariner-release",
					Version: "2.0",
					Release: "12.cm2",
					Arch:    "noarch",
				},
				{
					Name:    "filesystem",
					Version: "1.1",
					Release: "9.cm2",
					Arch:    "x86_64",
				},
				{
					Name:    "glibc",
					Version: "2.35",
					Release: "2.cm2",
					Arch:    "x86_64",
				},
			},
		},
		{
			name:    "sab path",
			content: "filesystem\t1.1-7.cm1\t1653164283\t1599428094",
			wantErr: "failed to split source rpm: wrong number of variables",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := marinerDistrolessPkgAnalyzer{}
			result, err := a.parseMarinerDistrolessManifest(strings.NewReader(test.content))
			if test.wantErr != "" {
				assert.NotNil(t, err)
				assert.Equal(t, test.wantErr, err.Error())
			} else {
				assert.Nil(t, err)
				assert.Equal(t, test.wantPkgs, result)
			}
		})
	}
}

func TestSplitSourceRpm(t *testing.T) {
	tests := []struct {
		name        string
		filepath    string
		wantName    string
		wantVersion string
		wantRelease string
		wantErr     string
	}{
		{
			name:        "happy path",
			filepath:    "distroless-packages-0.1-2.cm2.src.rpm",
			wantName:    "distroless-packages",
			wantVersion: "0.1",
			wantRelease: "2.cm2",
		},
		{
			name:     "sad path. Bad suffix",
			filepath: "distroless-packages-0.1-2.cm2.src",
			wantErr:  "sourceRPM doesn't contain '.src.rpm' suffix: \"distroless-packages-0.1-2.cm2.src\"",
		},
		{
			name:     "sad path. No release",
			filepath: "filesystem 1.1 9.cm2.src.rpm",
			wantErr:  "sourceRPM doesn't contain release: \"filesystem 1.1 9.cm2\"",
		},
		{
			name:     "sad path. No version",
			filepath: "filesystem 1.1-9.cm2.src.rpm",
			wantErr:  "sourceRPM doesn't contain version: \"filesystem 1.1-9.cm2\"",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name, ver, rel, err := splitSourceRpm(test.filepath)
			if test.wantErr != "" {
				assert.NotNil(t, err)
				assert.Equal(t, test.wantErr, err.Error())
			} else {
				assert.Nil(t, err)
				assert.Equal(t, test.wantName, name)
				assert.Equal(t, test.wantRelease, rel)
				assert.Equal(t, test.wantVersion, ver)
			}
		})
	}
}
