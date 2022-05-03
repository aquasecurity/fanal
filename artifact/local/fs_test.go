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
	"github.com/aquasecurity/fanal/types"

	_ "github.com/aquasecurity/fanal/analyzer/language/python/pip"
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/fanal/handler/misconf"
	_ "github.com/aquasecurity/fanal/handler/sysfile"
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
		disabledHandlers   []types.HandlerType
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
					BlobID: "sha256:5f1b3e9c7293a60f38a30a622d6cc282e8f658e35ca09989181a080716b7a26d",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						OS: &types.OS{
							Family: "alpine",
							Name:   "3.11.6",
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
				ID:   "sha256:5f1b3e9c7293a60f38a30a622d6cc282e8f658e35ca09989181a080716b7a26d",
				BlobIDs: []string{
					"sha256:5f1b3e9c7293a60f38a30a622d6cc282e8f658e35ca09989181a080716b7a26d",
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
					BlobID: "sha256:81994e090730351f860056e7dc945f781b10f4bfaefc81302b3cb1735bab0aff",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "host",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:81994e090730351f860056e7dc945f781b10f4bfaefc81302b3cb1735bab0aff",
				BlobIDs: []string{
					"sha256:81994e090730351f860056e7dc945f781b10f4bfaefc81302b3cb1735bab0aff",
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
					BlobID: "sha256:5f1b3e9c7293a60f38a30a622d6cc282e8f658e35ca09989181a080716b7a26d",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						OS: &types.OS{
							Family: "alpine",
							Name:   "3.11.6",
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
					BlobID: "sha256:cef17cdd60425bd6351d880d6dd2844f4cd4b6243e74ec2db3f9b6b2c3aaf88a",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
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
				ID:   "sha256:cef17cdd60425bd6351d880d6dd2844f4cd4b6243e74ec2db3f9b6b2c3aaf88a",
				BlobIDs: []string{
					"sha256:cef17cdd60425bd6351d880d6dd2844f4cd4b6243e74ec2db3f9b6b2c3aaf88a",
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
					BlobID: "sha256:cef17cdd60425bd6351d880d6dd2844f4cd4b6243e74ec2db3f9b6b2c3aaf88a",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
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
				ID:   "sha256:cef17cdd60425bd6351d880d6dd2844f4cd4b6243e74ec2db3f9b6b2c3aaf88a",
				BlobIDs: []string{
					"sha256:cef17cdd60425bd6351d880d6dd2844f4cd4b6243e74ec2db3f9b6b2c3aaf88a",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockArtifactCache)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)

			a, err := NewArtifact(tt.fields.dir, c, tt.artifactOpt)
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

func TestTerraformMisconfigurationScan(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		artifactOpt        artifact.Option
		want               types.ArtifactReference
	}{
		{
			name: "single failure",
			fields: fields{
				dir: "./testdata/misconfig/terraform/single-failure/src",
			},
			artifactOpt: artifact.Option{
				AnalyzerGroup:     "",
				DisabledAnalyzers: nil,
				DisabledHandlers:  nil,
				SkipFiles:         nil,
				SkipDirs:          nil,
				NoProgress:        false,
				Offline:           false,
				InsecureSkipTLS:   false,
				MisconfScannerOption: config.ScannerOption{
					RegoOnly:    true,
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/terraform/single-failure/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType:  "terraform",
								FilePath:  "testdata/misconfig/terraform/single-failure/src/main.tf",
								Successes: nil,
								Warnings:  nil,
								Failures: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											Type:               "Terraform Security Check",
											Title:              "Test policy",
											Description:        "",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										IacMetadata: types.IacMetadata{
											Resource:  "aws_s3_bucket.asd",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
										},
										Traces: nil,
									},
								},
								Exceptions: nil,
								Layer:      types.Layer{},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/terraform/single-failure/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:d0d8a0cf78ff2366e8313fdc63f5f8f3fdf4363b523222962fb10fedbdc67632",
				BlobIDs: []string{
					"sha256:d0d8a0cf78ff2366e8313fdc63f5f8f3fdf4363b523222962fb10fedbdc67632",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/terraform/multiple-failures/src",
			},
			artifactOpt: artifact.Option{
				AnalyzerGroup:     "",
				DisabledAnalyzers: nil,
				DisabledHandlers:  nil,
				SkipFiles:         nil,
				SkipDirs:          nil,
				NoProgress:        false,
				Offline:           false,
				InsecureSkipTLS:   false,
				MisconfScannerOption: config.ScannerOption{
					RegoOnly:    true,
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/terraform/multiple-failures/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType:  "terraform",
								FilePath:  "testdata/misconfig/terraform/multiple-failures/src/main.tf",
								Successes: nil,
								Warnings:  nil,
								Failures: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											Type:               "Terraform Security Check",
											Title:              "Test policy",
											Description:        "",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										IacMetadata: types.IacMetadata{
											Resource:  "aws_s3_bucket.two",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 5,
											EndLine:   7,
										},
										Traces: nil,
									},
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											Type:               "Terraform Security Check",
											Title:              "Test policy",
											Description:        "",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										IacMetadata: types.IacMetadata{
											Resource:  "aws_s3_bucket.one",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
										},
										Traces: nil,
									},
								},
								Exceptions: nil,
								Layer:      types.Layer{},
							},
							{
								FileType:  "terraform",
								FilePath:  "testdata/misconfig/terraform/multiple-failures/src/more.tf",
								Successes: nil,
								Warnings:  nil,
								Failures: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											Type:               "Terraform Security Check",
											Title:              "Test policy",
											Description:        "",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										IacMetadata: types.IacMetadata{
											Resource:  "aws_s3_bucket.three",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 2,
											EndLine:   4,
										},
										Traces: nil,
									},
								},
								Exceptions: nil,
								Layer:      types.Layer{},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/terraform/multiple-failures/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:7a92b0a41ec7a87a373106709aa765d65df87abcb1a149d44425706381b35dab",
				BlobIDs: []string{
					"sha256:7a92b0a41ec7a87a373106709aa765d65df87abcb1a149d44425706381b35dab",
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: "./testdata/misconfig/terraform/no-results/src",
			},
			artifactOpt: artifact.Option{
				AnalyzerGroup:     "",
				DisabledAnalyzers: nil,
				DisabledHandlers:  nil,
				SkipFiles:         nil,
				SkipDirs:          nil,
				NoProgress:        false,
				Offline:           false,
				InsecureSkipTLS:   false,
				MisconfScannerOption: config.ScannerOption{
					RegoOnly:    true,
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/terraform/no-results/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/terraform/no-results/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:9080fe76e2caee45bb22dec349afa0d631efc8e82f49561e25ee48c0f0c2d0b5",
				BlobIDs: []string{
					"sha256:9080fe76e2caee45bb22dec349afa0d631efc8e82f49561e25ee48c0f0c2d0b5",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/terraform/passed/src",
			},
			artifactOpt: artifact.Option{
				AnalyzerGroup:     "",
				DisabledAnalyzers: nil,
				DisabledHandlers:  nil,
				SkipFiles:         nil,
				SkipDirs:          nil,
				NoProgress:        false,
				Offline:           false,
				InsecureSkipTLS:   false,
				MisconfScannerOption: config.ScannerOption{
					RegoOnly:    true,
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/terraform/passed/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "terraform",
								FilePath: "testdata/misconfig/terraform/passed/src",
								Successes: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											Type:               "Terraform Security Check",
											Title:              "Test policy",
											Description:        "",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										IacMetadata: types.IacMetadata{
											Resource:  "",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 0,
											EndLine:   0,
										},
										Traces: nil,
									},
								},
								Layer: types.Layer{},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/terraform/passed/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:c0b8f9e1d50ff44ff6a9111baebff2cdab5a6f7fc9fffaed5040e5142c676bda",
				BlobIDs: []string{
					"sha256:c0b8f9e1d50ff44ff6a9111baebff2cdab5a6f7fc9fffaed5040e5142c676bda",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockArtifactCache)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)
			tt.artifactOpt.DisabledHandlers = []types.HandlerType{
				types.SystemFileFilteringPostHandler,
				types.GoModMergePostHandler,
			}
			a, err := NewArtifact(tt.fields.dir, c, tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
