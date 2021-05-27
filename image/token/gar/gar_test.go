package gar

import (
	"reflect"
	"testing"

	"github.com/GoogleCloudPlatform/docker-credential-gcr/store"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/types"
)

func TestCheckOptions(t *testing.T) {
	var tests = map[string]struct {
		domain  string
		opt     types.DockerOption
		gar     *GAR
		wantErr error
	}{
		"InvalidURL": {
			domain:  "alpine:3.9",
			opt:     types.DockerOption{},
			wantErr: types.InvalidURLPattern,
		},
		"NoOption": {
			domain: "docker.pkg.dev",
			opt:    types.DockerOption{},
			gar:    &GAR{domain: "docker.pkg.dev"},
		},
		"CredOption": {
			domain: "docker.pkg.dev",
			opt:    types.DockerOption{GcpCredPath: "/path/to/file.json"},
			gar:    &GAR{domain: "docker.pkg.dev", Store: store.NewGCRCredStore("/path/to/file.json")},
		},
	}

	for testname, v := range tests {
		g := &GAR{}
		err := g.CheckOptions(v.domain, v.opt)
		if v.wantErr != nil {
			if err == nil {
				t.Errorf("%s : expected error but no error", testname)
				continue
			}
			if !xerrors.Is(err, v.wantErr) {
				t.Errorf("[%s]\nexpected error based on %v\nactual : %v", testname, v.wantErr, err)
			}
			continue
		}
		if !reflect.DeepEqual(v.gar, g) {
			t.Errorf("[%s]\nexpected : %v\nactual : %v", testname, v.gar, g)
		}
	}
}
