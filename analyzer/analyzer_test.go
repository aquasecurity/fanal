package analyzer_test

import (
	"errors"
	"io/ioutil"
	"os"
	"testing"

	_ "github.com/aquasecurity/fanal/analyzer/library/bundler"
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/os/ubuntu"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"

	_ "github.com/aquasecurity/fanal/analyzer/library/bundler"
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/os/ubuntu"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"

	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"

	"github.com/aquasecurity/fanal/analyzer"
	"golang.org/x/xerrors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/types"
)

func TestAnalyzeFile(t *testing.T) {
	type args struct {
		filePath string
		info     os.FileInfo
		opener   analyzer.Opener
	}
	tests := []struct {
		name    string
		args    args
		want    *analyzer.AnalysisResult
		wantErr string
	}{
		{
			name: "happy path with os analyzer",
			args: args{
				filePath: "/etc/alpine-release",
				opener: func() ([]byte, error) {
					return ioutil.ReadFile("testdata/etc/alpine-release")
				},
			},
			want: &analyzer.AnalysisResult{
				OS: &types.OS{
					Family: "alpine",
					Name:   "3.11.6",
				},
			},
		},
		{
			name: "happy path with package analyzer",
			args: args{
				filePath: "/lib/apk/db/installed",
				opener: func() ([]byte, error) {
					return ioutil.ReadFile("testdata/lib/apk/db/installed")
				},
			},
			want: &analyzer.AnalysisResult{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "/lib/apk/db/installed",
						Packages: []types.Package{
							{Name: "musl", Version: "1.1.24-r2"},
						},
					},
				},
			},
		},
		{
			name: "happy path with library analyzer",
			args: args{
				filePath: "/app/Gemfile.lock",
				opener: func() ([]byte, error) {
					return ioutil.ReadFile("testdata/app/Gemfile.lock")
				},
			},
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     "bundler",
						FilePath: "/app/Gemfile.lock",
						Libraries: []types.LibraryInfo{
							{
								Library: godeptypes.Library{
									Name:    "actioncable",
									Version: "5.2.3",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path with invalid os information",
			args: args{
				filePath: "/etc/lsb-release",
				opener: func() ([]byte, error) {
					return []byte(`foo`), nil
				},
			},
			want: &analyzer.AnalysisResult{},
		},
		{
			name: "sad path with opener error",
			args: args{
				filePath: "/lib/apk/db/installed",
				opener: func() ([]byte, error) {
					return nil, xerrors.New("error")
				},
			},
			wantErr: "unable to open a file (/lib/apk/db/installed)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := analyzer.AnalyzeFile(tt.args.filePath, tt.args.info, tt.args.opener)
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

type mockConfigAnalyzer struct{}

func (mockConfigAnalyzer) Required(targetOS types.OS) bool {
	return targetOS.Family == "alpine"
}

func (mockConfigAnalyzer) Analyze(targetOS types.OS, configBlob []byte) ([]types.Package, error) {
	if string(configBlob) != `foo` {
		return nil, errors.New("error")
	}
	return []types.Package{
		{Name: "musl", Version: "1.1.24-r2"},
	}, nil
}

func TestAnalyzeConfig(t *testing.T) {
	analyzer.RegisterConfigAnalyzer(mockConfigAnalyzer{})

	type args struct {
		targetOS   types.OS
		configBlob []byte
	}
	tests := []struct {
		name string
		args args
		want []types.Package
	}{
		{
			name: "happy path",
			args: args{
				targetOS: types.OS{
					Family: "alpine",
					Name:   "3.11.6",
				},
				configBlob: []byte("foo"),
			},
			want: []types.Package{
				{Name: "musl", Version: "1.1.24-r2"},
			},
		},
		{
			name: "non-target OS",
			args: args{
				targetOS: types.OS{
					Family: "debian",
					Name:   "9.2",
				},
				configBlob: []byte("foo"),
			},
		},
		{
			name: "Analyze returns an error",
			args: args{
				targetOS: types.OS{
					Family: "alpine",
					Name:   "3.11.6",
				},
				configBlob: []byte("bar"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.AnalyzeConfig(tt.args.targetOS, tt.args.configBlob)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCheckPackage(t *testing.T) {
	tests := []struct {
		name string
		pkg  *types.Package
		want bool
	}{
		{
			name: "valid package",
			pkg: &types.Package{
				Name:    "musl",
				Version: "1.2.3",
			},
			want: true,
		},
		{
			name: "empty name",
			pkg: &types.Package{
				Name:    "",
				Version: "1.2.3",
			},
			want: false,
		},
		{
			name: "empty version",
			pkg: &types.Package{
				Name:    "musl",
				Version: "",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.CheckPackage(tt.pkg)
			assert.Equal(t, tt.want, got)
		})
	}
}
