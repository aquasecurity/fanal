package remote

import (
	"net/http"
	"net/http/httptest"
	"testing"

	git "github.com/go-git/go-git/v5"
	"github.com/sosedoff/gitkit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/cache"
	remotecfg "github.com/aquasecurity/fanal/remote"
)

func setupGitServer() (*httptest.Server, error) {
	service := gitkit.New(gitkit.Config{
		Dir:        "./testdata",
		AutoCreate: false,
	})

	if err := service.Setup(); err != nil {
		return nil, err
	}

	http.Handle("/", service)
	ts := httptest.NewServer(service)

	return ts, nil
}

func TestNewArtifact(t *testing.T) {
	ts, err := setupGitServer()
	require.NoError(t, err)
	defer ts.Close()

	type args struct {
		remote remotecfg.Remote
		c      cache.ArtifactCache
	}
	tests := []struct {
		name    string
		args    args
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				remote: remotecfg.Remote{
					IsBare: false,
					CloneOpts: &git.CloneOptions{
						URL:   ts.URL + "/test.git",
						Depth: 1,
					},
				},
				c: nil,
			},
		},
		{
			name: "happy path commit",
			args: args{
				remote: remotecfg.Remote{
					IsBare: false,
					Commit: "HEAD~1",
					CloneOpts: &git.CloneOptions{
						URL:   ts.URL + "/test.git",
						Depth: 1,
					},
				},
				c: nil,
			},
		},
		{
			name: "sad path unknown repo",
			args: args{
				remote: remotecfg.Remote{
					IsBare: false,
					CloneOpts: &git.CloneOptions{
						URL:   ts.URL + "/unknown.git",
						Depth: 1,
					},
				},
				c: nil,
			},
			wantErr: "repository not found",
		},
		{
			name: "sad path unknown commit",
			args: args{
				remote: remotecfg.Remote{
					IsBare: false,
					Commit: "baddigest",
					CloneOpts: &git.CloneOptions{
						URL:   ts.URL + "/test.git",
						Depth: 1,
					},
				},
				c: nil,
			},
			wantErr: "object not found",
		},
		{
			name: "invalid url",
			args: args{
				remote: remotecfg.Remote{
					IsBare: false,
					CloneOpts: &git.CloneOptions{
						URL:   "ht tp://foo.com",
						Depth: 1,
					},
				},
				c: nil,
			},
			wantErr: "first path segment in URL cannot contain colon",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, cleanup, err := NewArtifact(tt.args.remote, tt.args.c, nil)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			defer cleanup()
		})
	}
}

func Test_newURL(t *testing.T) {
	type args struct {
		rawurl string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				rawurl: "https://github.com/aquasecurity/fanal",
			},
			want: "https://github.com/aquasecurity/fanal",
		},
		{
			name: "happy path: no scheme",
			args: args{
				rawurl: "github.com/aquasecurity/fanal",
			},
			want: "https://github.com/aquasecurity/fanal",
		},
		{
			name: "happy path: ssh url",
			args: args{
				rawurl: "github.com:foo/bar",
			},
			want: "github.com:foo/bar",
		},
		{
			name: "sad path: invalid url",
			args: args{
				rawurl: "ht tp://foo.com",
			},
			wantErr: "first path segment in URL cannot contain colon",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newURL(tt.args.rawurl)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.want, got)
		})
	}
}
