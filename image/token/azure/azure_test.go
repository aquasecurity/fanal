package azure

import (
	"reflect"
	"testing"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/types"
)

func TestCheckOptions(t *testing.T) {
	var tests = map[string]struct {
		domain  string
		opt     types.DockerOption
		azure   *Registry
		wantErr error
	}{
		"InvalidURL": {
			domain:  "alpine:3.9",
			opt:     types.DockerOption{},
			wantErr: types.InvalidURLPattern,
		},
		"NoOption": {
			domain: "test.azurecr.io",
			opt:    types.DockerOption{},
			azure:  &Registry{domain: "test.azurecr.io"},
		},
		"CredOption": {
			domain: "test.azurecr.io",
			opt:    types.DockerOption{GcpCredPath: "/path/to/file.json"},
			azure:  &Registry{domain: "test.azurecr.io"},
		},
	}

	for testname, v := range tests {
		g := &Registry{}
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
		if !reflect.DeepEqual(v.azure, g) {
			t.Errorf("[%s]\nexpected : %v\nactual : %v", testname, v.azure, g)
		}
	}
}
