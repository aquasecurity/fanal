package analyzer_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"golang.org/x/xerrors"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"

	_ "github.com/aquasecurity/fanal/analyzer/command/apk"
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"

	"github.com/aquasecurity/fanal/extractor/docker"
	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/types"
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
		putLayerExpectation     cache.PutLayerExpectation
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
			putLayerExpectation: cache.PutLayerExpectation{
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
			want: types.ImageInfo{
				Name:     "testdata/alpine.tar.gz",
				ID:       "sha256:965ea09ff2ebd2b9eeec88cd822ce156f6674c7e99be082c7efac3c62f3ff652",
				LayerIDs: []string{"sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0"},
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
			putLayerExpectation: cache.PutLayerExpectation{
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
			wantErr: "put layer failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCache := new(cache.MockLayerCache)
			mockCache.ApplyMissingLayersExpectation(tt.missingLayerExpectation)
			mockCache.ApplyPutLayerExpectation(tt.putLayerExpectation)

			d, err := docker.NewDockerArchiveExtractor(context.Background(), tt.imagePath, types.DockerOption{})
			assert.NoError(t, err, tt.name)

			ac := analyzer.Config{
				Extractor: d,
				Cache:     mockCache,
			}
			got, err := ac.Analyze(context.Background())
			if tt.wantErr != "" {
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			} else {
				require.NoError(t, err, tt.name)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Analyze() got = %v, want %v", got, tt.want)
			}
		})
	}
}
