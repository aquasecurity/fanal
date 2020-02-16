package analyzer_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	_ "github.com/aquasecurity/fanal/analyzer/command/apk"
	_ "github.com/aquasecurity/fanal/analyzer/library/composer"
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/os/debianbase"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/dpkg"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/extractor/docker"
	"github.com/aquasecurity/fanal/types"
	depTypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestConfig_Analyze(t *testing.T) {
	type fields struct {
		Extractor extractor.Extractor
		Cache     cache.LayerCache
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name                    string
		imagePath               string
		fields                  fields
		args                    args
		missingLayerExpectation cache.MissingLayersExpectation
		putLayerExpectations    []cache.PutLayerExpectation
		want                    types.ImageInfo
		wantErr                 string
	}{
		{
			name:      "happy path",
			imagePath: "testdata/alpine.tar.gz",
			missingLayerExpectation: cache.MissingLayersExpectation{
				Args: cache.MissingLayersArgs{
					LayerIDs: []string{"sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0"},
				},
				Returns: cache.MissingLayersReturns{
					MissingLayerIDs: []string{"sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0"},
				},
			},
			putLayerExpectations: []cache.PutLayerExpectation{
				{
					Args: cache.PutLayerArgs{
						LayerID:             "sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0",
						DecompressedLayerID: "sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0",
						LayerInfo: types.LayerInfo{
							SchemaVersion: 1,
							OS: &types.OS{
								Family: "alpine",
								Name:   "3.10.3",
							},
							PackageInfos:  []types.PackageInfo{{FilePath: "lib/apk/db/installed", Packages: []types.Package{{Name: "musl", Version: "1.1.22-r3", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "busybox", Version: "1.30.1-r2", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "alpine-baselayout", Version: "3.1.2-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "alpine-keys", Version: "2.1-r2", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "openssl", Version: "1.1.1d-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "libcrypto1.1", Version: "1.1.1d-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "libssl1.1", Version: "1.1.1d-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "ca-certificates", Version: "20190108-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "ca-certificates-cacert", Version: "20190108-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "libtls-standalone", Version: "2.9.1-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "ssl_client", Version: "1.30.1-r2", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "zlib", Version: "1.2.11-r1", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "apk-tools", Version: "2.10.4-r2", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "pax-utils", Version: "1.2.3-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "scanelf", Version: "1.2.3-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "musl-utils", Version: "1.1.22-r3", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "libc-dev", Version: "0.7.1-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "libc-utils", Version: "0.7.1-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}}}},
							Applications:  []types.Application(nil),
							OpaqueDirs:    []string(nil),
							WhiteoutFiles: []string(nil),
						},
					},
					Returns: cache.PutLayerReturns{},
				},
			},
			want: types.ImageInfo{
				Name:     "testdata/alpine.tar.gz",
				ID:       "sha256:965ea09ff2ebd2b9eeec88cd822ce156f6674c7e99be082c7efac3c62f3ff652",
				LayerIDs: []string{"sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0"},
			},
		},
		{
			name:      "happy path: include lock files",
			imagePath: "testdata/vuln-image.tar.gz",
			missingLayerExpectation: cache.MissingLayersExpectation{
				Args: cache.MissingLayersArgs{
					LayerIDs: []string{"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02", "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5", "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7", "sha256:a4595c43a874856bf95f3bfc4fbf78bbaa04c92c726276d4f64193a47ced0566"},
				},
				Returns: cache.MissingLayersReturns{
					MissingLayerIDs: []string{"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02", "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5", "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7"},
				},
			},
			putLayerExpectations: []cache.PutLayerExpectation{
				{
					Args: cache.PutLayerArgs{
						LayerID:             "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						DecompressedLayerID: "sha256:d9441f7754ba1423ee11793b5db6390256e44097c2fc25e75a5fab19e6dc7911",
						LayerInfo: types.LayerInfo{
							SchemaVersion: 1,
							OS:            &types.OS{Family: "debian", Name: "9.9"},
							PackageInfos:  []types.PackageInfo{{FilePath: "var/lib/dpkg/status.d/base", Packages: []types.Package{{Name: "base-files", Version: "9.9+deb9u9", Release: "", Epoch: 0, Arch: "", SrcName: "base-files", SrcVersion: "9.9+deb9u9", SrcRelease: "", SrcEpoch: 0}}}, {FilePath: "var/lib/dpkg/status.d/netbase", Packages: []types.Package{{Name: "netbase", Version: "5.4", Release: "", Epoch: 0, Arch: "", SrcName: "netbase", SrcVersion: "5.4", SrcRelease: "", SrcEpoch: 0}}}, {FilePath: "var/lib/dpkg/status.d/tzdata", Packages: []types.Package{{Name: "tzdata", Version: "2019a-0+deb9u1", Release: "", Epoch: 0, Arch: "", SrcName: "tzdata", SrcVersion: "2019a-0+deb9u1", SrcRelease: "", SrcEpoch: 0}}}},
						},
					},
				},
				{
					Args: cache.PutLayerArgs{
						LayerID:             "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
						DecompressedLayerID: "sha256:dab15cac9ebd43beceeeda3ce95c574d6714ed3d3969071caead678c065813ec",
						LayerInfo: types.LayerInfo{
							SchemaVersion: 1,
							PackageInfos:  []types.PackageInfo{{FilePath: "var/lib/dpkg/status.d/libc6", Packages: []types.Package{{Name: "libc6", Version: "2.24-11+deb9u4", Release: "", Epoch: 0, Arch: "", SrcName: "glibc", SrcVersion: "2.24-11+deb9u4", SrcRelease: "", SrcEpoch: 0}}}, {FilePath: "var/lib/dpkg/status.d/libssl1", Packages: []types.Package{{Name: "libssl1.1", Version: "1.1.0k-1~deb9u1", Release: "", Epoch: 0, Arch: "", SrcName: "openssl", SrcVersion: "1.1.0k-1~deb9u1", SrcRelease: "", SrcEpoch: 0}}}, {FilePath: "var/lib/dpkg/status.d/openssl", Packages: []types.Package{{Name: "openssl", Version: "1.1.0k-1~deb9u1", Release: "", Epoch: 0, Arch: "", SrcName: "openssl", SrcVersion: "1.1.0k-1~deb9u1", SrcRelease: "", SrcEpoch: 0}}}},
						},
					},
				},
				{
					Args: cache.PutLayerArgs{
						LayerID:             "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
						DecompressedLayerID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
						LayerInfo: types.LayerInfo{
							SchemaVersion: 1,
							Applications:  []types.Application{{Type: "composer", FilePath: "php-app/composer.lock", Libraries: []depTypes.Library{{Name: "guzzlehttp/guzzle", Version: "6.2.0"}, {Name: "guzzlehttp/promises", Version: "v1.3.1"}, {Name: "guzzlehttp/psr7", Version: "1.5.2"}, {Name: "laravel/installer", Version: "v2.0.1"}, {Name: "pear/log", Version: "1.13.1"}, {Name: "pear/pear_exception", Version: "v1.0.0"}, {Name: "psr/http-message", Version: "1.0.1"}, {Name: "ralouphie/getallheaders", Version: "2.0.5"}, {Name: "symfony/console", Version: "v4.2.7"}, {Name: "symfony/contracts", Version: "v1.0.2"}, {Name: "symfony/filesystem", Version: "v4.2.7"}, {Name: "symfony/polyfill-ctype", Version: "v1.11.0"}, {Name: "symfony/polyfill-mbstring", Version: "v1.11.0"}, {Name: "symfony/process", Version: "v4.2.7"}}}},
							OpaqueDirs:    []string{"php-app/"},
						},
					},
				},
			},
			want: types.ImageInfo{
				Name:     "testdata/vuln-image.tar.gz",
				ID:       "sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4",
				LayerIDs: []string{"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02", "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5", "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7", "sha256:a4595c43a874856bf95f3bfc4fbf78bbaa04c92c726276d4f64193a47ced0566"},
			},
		},
		{
			name:      "sad path, MissingLayers returns an error",
			imagePath: "testdata/alpine.tar.gz",
			missingLayerExpectation: cache.MissingLayersExpectation{
				Args: cache.MissingLayersArgs{
					LayerIDs: []string{"sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0"},
				},
				Returns: cache.MissingLayersReturns{
					Err: xerrors.New("MissingLayers failed"),
				},
			},
			wantErr: "MissingLayers failed",
		},
		{
			name:      "sad path, PutLayer returns an error",
			imagePath: "testdata/alpine.tar.gz",
			missingLayerExpectation: cache.MissingLayersExpectation{
				Args: cache.MissingLayersArgs{
					LayerIDs: []string{"sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0"},
				},
				Returns: cache.MissingLayersReturns{
					MissingLayerIDs: []string{"sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0"},
				},
			},
			putLayerExpectations: []cache.PutLayerExpectation{
				{
					Args: cache.PutLayerArgs{
						LayerID:             "sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0",
						DecompressedLayerID: "sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0",
						LayerInfo: types.LayerInfo{
							SchemaVersion: 1,
							OS: &types.OS{
								Family: "alpine",
								Name:   "3.10.3",
							},
							PackageInfos:  []types.PackageInfo{{FilePath: "lib/apk/db/installed", Packages: []types.Package{{Name: "musl", Version: "1.1.22-r3", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "busybox", Version: "1.30.1-r2", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "alpine-baselayout", Version: "3.1.2-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "alpine-keys", Version: "2.1-r2", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "openssl", Version: "1.1.1d-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "libcrypto1.1", Version: "1.1.1d-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "libssl1.1", Version: "1.1.1d-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "ca-certificates", Version: "20190108-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "ca-certificates-cacert", Version: "20190108-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "libtls-standalone", Version: "2.9.1-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "ssl_client", Version: "1.30.1-r2", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "zlib", Version: "1.2.11-r1", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "apk-tools", Version: "2.10.4-r2", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "pax-utils", Version: "1.2.3-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "scanelf", Version: "1.2.3-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "musl-utils", Version: "1.1.22-r3", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "libc-dev", Version: "0.7.1-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "libc-utils", Version: "0.7.1-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}}}},
							Applications:  []types.Application(nil),
							OpaqueDirs:    []string(nil),
							WhiteoutFiles: []string(nil),
						},
					},
					Returns: cache.PutLayerReturns{
						Err: errors.New("put layer failed"),
					},
				},
			},
			wantErr: "put layer failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCache := new(cache.MockLayerCache)
			mockCache.ApplyMissingLayersExpectation(tt.missingLayerExpectation)
			mockCache.ApplyPutLayerExpectations(tt.putLayerExpectations)

			d, err := docker.NewDockerArchiveExtractor(context.Background(), tt.imagePath, types.DockerOption{})
			assert.NoError(t, err, tt.name)

			ac := analyzer.Config{
				Extractor: d,
				Cache:     mockCache,
			}
			got, err := ac.Analyze(context.Background())
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			} else {
				require.NoError(t, err, tt.name)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
