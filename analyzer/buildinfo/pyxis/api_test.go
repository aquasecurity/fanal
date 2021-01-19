package pyxis_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/fanal/analyzer/buildinfo/pyxis"
)

func TestPyxis_FetchContentSets(t *testing.T) {
	type data struct {
		ContentSets []string `json:"content_sets"`
	}
	type response struct {
		Data []data
	}

	type args struct {
		nvr  string
		arch string
	}
	tests := []struct {
		name     string
		args     args
		response response
		want     []string
		wantErr  string
	}{
		{
			name: "happy path",
			args: args{
				nvr:  "ubi8-container-8.3-227",
				arch: "x86_64",
			},
			response: response{
				Data: []data{
					{ContentSets: []string{"rhel-8-for-ppc64le-baseos-rpms", "rhel-8-for-ppc64le-appstream-rpms"}},
				},
			},
			want: []string{
				"rhel-8-for-ppc64le-baseos-rpms",
				"rhel-8-for-ppc64le-appstream-rpms",
			},
		},
		{
			name: "two blocks",
			args: args{
				nvr:  "ubi8-container-8.3-227",
				arch: "x86_64",
			},
			response: response{
				Data: []data{
					{ContentSets: []string{"rhel-8-for-ppc64le-baseos-rpms"}},
					{ContentSets: []string{"rhel-8-for-ppc64le-appstream-rpms"}},
				},
			},
			wantErr: "the response must have only one block",
		},
		{
			name: "broken JSON",
			args: args{
				nvr:  "ubi8-container-8.3-227",
				arch: "x86_64",
			},
			wantErr: "JSON parse error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				if len(tt.response.Data) == 0 {
					_, _ = res.Write([]byte("broken"))
					return
				}
				b, err := json.Marshal(tt.response)
				if err != nil {
					http.Error(res, err.Error(), http.StatusInternalServerError)
				}
				_, _ = res.Write(b)
			}))

			url := ts.URL + "/api/containers/v1/images/nvr/%s?filter=parsed_data.labels=em=(name=='architecture'andvalue=='%s')"
			p := pyxis.NewPyxis(pyxis.WithURL(url))
			got, err := p.FetchContentSets(tt.args.nvr, tt.args.arch)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
