package local

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/hook"
	"github.com/aquasecurity/fanal/types"

	_ "github.com/aquasecurity/fanal/analyzer/language/python/pip"
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/fanal/hook/all"
)

func TestArtifact_Inspect(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
		artifactOpt        artifact.Option
		scannerOpt         config.ScannerOption
		disabledAnalyzers  []analyzer.Type
		disabledHooks      []hook.Type
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		want               types.ArtifactReference
		wantErr            string
	}{
		{
			name: "happy path",
			fields: fields{
				dir: "./testdata/alpine",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:5478476699d3ecc79cc8f4f18538d33eecfe13b871a4d7c69ba33a278fb39e1f",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						DiffID:        "sha256:62a8fb607bf4a226af3cb30ec4e020c4544f750cd34d1f4f8e35ff9bffc7d3f2",
						OS: &types.OS{
							Family:   "alpine",
							Name:     "3.11.6",
							Priority: 2,
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
									{Name: "musl", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2", License: "MIT"},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "host",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:5478476699d3ecc79cc8f4f18538d33eecfe13b871a4d7c69ba33a278fb39e1f",
				BlobIDs: []string{
					"sha256:5478476699d3ecc79cc8f4f18538d33eecfe13b871a4d7c69ba33a278fb39e1f",
				},
			},
		},
		{
			name: "disable analyzers",
			fields: fields{
				dir: "./testdata/alpine",
			},
			artifactOpt: artifact.Option{
				DisabledAnalyzers: []analyzer.Type{analyzer.TypeAlpine, analyzer.TypeApk, analyzer.TypePip},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:c7edf2dea9d30af500d593ab40cac2615d92f569929299e7517948f7b5466c19",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						DiffID:        "sha256:8ad5ef100e762e3f4df37beb3f8231a782cea12ad9d39bda13fd5850d1b15d11",
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "host",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:c7edf2dea9d30af500d593ab40cac2615d92f569929299e7517948f7b5466c19",
				BlobIDs: []string{
					"sha256:c7edf2dea9d30af500d593ab40cac2615d92f569929299e7517948f7b5466c19",
				},
			},
		},
		{
			name: "sad path PutBlob returns an error",
			fields: fields{
				dir: "./testdata/alpine",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:5478476699d3ecc79cc8f4f18538d33eecfe13b871a4d7c69ba33a278fb39e1f",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						DiffID:        "sha256:62a8fb607bf4a226af3cb30ec4e020c4544f750cd34d1f4f8e35ff9bffc7d3f2",
						OS: &types.OS{
							Family:   "alpine",
							Name:     "3.11.6",
							Priority: 2,
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
									{Name: "musl", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2", License: "MIT"},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{
					Err: errors.New("error"),
				},
			},
			wantErr: "failed to store blob",
		},
		{
			name: "sad path with no such directory",
			fields: fields{
				dir: "./testdata/unknown",
			},
			wantErr: "no such file or directory",
		},
		{
			name: "happy path with single file",
			fields: fields{
				dir: "testdata/requirements.txt",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:4750c846cf79661482e71dfc0a89b16463cda5c53c62d5885acaa874056f8b92",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						DiffID:        "sha256:de52b03af926ba8f646bd11b794f014161b11a3dbad0213d556ea9af120e1623",
						Applications: []types.Application{
							{
								Type:     "pip",
								FilePath: "requirements.txt",
								Libraries: []types.Package{
									{
										Name:    "Flask",
										Version: "2.0.0",
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/requirements.txt",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:4750c846cf79661482e71dfc0a89b16463cda5c53c62d5885acaa874056f8b92",
				BlobIDs: []string{
					"sha256:4750c846cf79661482e71dfc0a89b16463cda5c53c62d5885acaa874056f8b92",
				},
			},
		},
		{
			name: "happy path with single file using relative path",
			fields: fields{
				dir: "./testdata/requirements.txt",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:4750c846cf79661482e71dfc0a89b16463cda5c53c62d5885acaa874056f8b92",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						DiffID:        "sha256:de52b03af926ba8f646bd11b794f014161b11a3dbad0213d556ea9af120e1623",
						Applications: []types.Application{
							{
								Type:     "pip",
								FilePath: "requirements.txt",
								Libraries: []types.Package{
									{
										Name:    "Flask",
										Version: "2.0.0",
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/requirements.txt",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:4750c846cf79661482e71dfc0a89b16463cda5c53c62d5885acaa874056f8b92",
				BlobIDs: []string{
					"sha256:4750c846cf79661482e71dfc0a89b16463cda5c53c62d5885acaa874056f8b92",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockArtifactCache)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)

			a, err := NewArtifact(tt.fields.dir, c, tt.artifactOpt, tt.scannerOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
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

func TestBuildAbsPath(t *testing.T) {
	tests := []struct {
		name          string
		base          string
		paths         []string
		expectedPaths []string
	}{
		{"absolute path", "/testBase", []string{"/testPath"}, []string{"/testPath"}},
		{"relative path", "/testBase", []string{"testPath"}, []string{"/testBase/testPath"}},
		{"path have '.'", "/testBase", []string{"./testPath"}, []string{"/testBase/testPath"}},
		{"path have '..'", "/testBase", []string{"../testPath/"}, []string{"/testPath"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := buildAbsPaths(test.base, test.paths)
			if len(test.paths) != len(got) {
				t.Errorf("paths not equals, expected: %s, got: %s", test.expectedPaths, got)
			} else {
				for i, path := range test.expectedPaths {
					if path != got[i] {
						t.Errorf("paths not equals, expected: %s, got: %s", test.expectedPaths, got)
					}
				}
			}
		})
	}
}
