// +build integration

package integration

import (
	"context"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/extractor/docker"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	dtypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/aquasecurity/fanal/analyzer/command/apk"
	_ "github.com/aquasecurity/fanal/analyzer/library/bundler"
	_ "github.com/aquasecurity/fanal/analyzer/library/cargo"
	_ "github.com/aquasecurity/fanal/analyzer/library/composer"
	_ "github.com/aquasecurity/fanal/analyzer/library/npm"
	_ "github.com/aquasecurity/fanal/analyzer/library/pipenv"
	_ "github.com/aquasecurity/fanal/analyzer/library/poetry"
	_ "github.com/aquasecurity/fanal/analyzer/library/yarn"
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/os/amazonlinux"
	_ "github.com/aquasecurity/fanal/analyzer/os/debianbase"
	_ "github.com/aquasecurity/fanal/analyzer/os/photon"
	_ "github.com/aquasecurity/fanal/analyzer/os/redhatbase"
	_ "github.com/aquasecurity/fanal/analyzer/os/suse"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/dpkg"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/rpm"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
)

func TestFanal_Library_DockerMode(t *testing.T) {
	testCases := []struct {
		name                 string
		imageName            string
		imageFile            string
		expectedFiles        []string
		expectedOS           analyzer.OS
		expectedPkgs         []analyzer.Package
		expectedPkgsFromCmds []analyzer.Package
		expectedLibraries    map[analyzer.FilePath][]godeptypes.Library
	}{
		{
			name:      "happy path, alpine:3.10",
			imageName: "alpine:3.10",
			imageFile: "testdata/fixtures/alpine-310.tar.gz",
			expectedOS: analyzer.OS{
				Name:   "3.10.2",
				Family: "alpine",
			},
			expectedFiles: []string{"etc/alpine-release", "etc/os-release", "lib/apk/db/installed", "/config"},
			expectedPkgs: []analyzer.Package{
				{Name: "musl", Version: "1.1.22-r3"},
				{Name: "busybox", Version: "1.30.1-r2"},
				{Name: "alpine-baselayout", Version: "3.1.2-r0"},
				{Name: "alpine-keys", Version: "2.1-r2"},
				{Name: "openssl", Version: "1.1.1c-r0"},
				{Name: "libcrypto1.1", Version: "1.1.1c-r0"},
				{Name: "libssl1.1", Version: "1.1.1c-r0"},
				{Name: "ca-certificates", Version: "20190108-r0"},
				{Name: "ca-certificates-cacert", Version: "20190108-r0"},
				{Name: "libtls-standalone", Version: "2.9.1-r0"},
				{Name: "ssl_client", Version: "1.30.1-r2"},
				{Name: "zlib", Version: "1.2.11-r1"},
				{Name: "apk-tools", Version: "2.10.4-r2"},
				{Name: "pax-utils", Version: "1.2.3-r0"},
				{Name: "scanelf", Version: "1.2.3-r0"},
				{Name: "musl-utils", Version: "1.1.22-r3"},
				{Name: "libc-dev", Version: "0.7.1-r0"},
				{Name: "libc-utils", Version: "0.7.1-r0"},
			},
			expectedLibraries: map[analyzer.FilePath][]godeptypes.Library{},
		},
	}

	for _, tc := range testCases {
		ctx := context.Background()
		d, _ := ioutil.TempDir("", "TestFanal_Library_*")
		defer func() {
			_ = os.RemoveAll(d)
		}()
		c, _ := cache.New(d)

		opt := types.DockerOption{
			Timeout:  600 * time.Second,
			SkipPing: true,
		}

		cli, err := client.NewClientWithOpts(client.FromEnv)
		require.NoError(t, err, tc.name)

		// ensure image doesnt already exists
		_, _ = cli.ImageRemove(ctx, tc.imageFile, dtypes.ImageRemoveOptions{
			Force:         true,
			PruneChildren: true,
		})

		testfile, err := os.Open(tc.imageFile)
		require.NoError(t, err)

		// load image into docker engine
		_, err = cli.ImageLoad(ctx, testfile, true)
		require.NoError(t, err, tc.name)

		// tag our image to something unique
		err = cli.ImageTag(ctx, "alpine:3.10", tc.imageFile)
		require.NoError(t, err, tc.name)

		ext, err := docker.NewDockerExtractor(opt, c)
		require.NoError(t, err, tc.name)
		ac := analyzer.Config{Extractor: ext}

		actualFiles, err := ac.Analyze(ctx, tc.imageFile)
		require.NoError(t, err)
		for file, _ := range actualFiles {
			assert.Contains(t, tc.expectedFiles, file, tc.name)
		}
		assert.Equal(t, len(tc.expectedFiles), len(actualFiles), tc.name)

		// check OS
		osFound, err := analyzer.GetOS(actualFiles)
		require.NoError(t, err)
		assert.Equal(t, tc.expectedOS, osFound, tc.name)

		// check Packages
		actualPkgs, err := analyzer.GetPackages(actualFiles)
		require.NoError(t, err)
		assert.Equal(t, tc.expectedPkgs, actualPkgs, tc.name)

		// check Packges from Commands
		actualPkgsFromCmds, err := analyzer.GetPackagesFromCommands(osFound, actualFiles)
		require.NoError(t, err)
		assert.Equal(t, tc.expectedPkgsFromCmds, actualPkgsFromCmds, tc.name)

		// check Libraries
		actualLibs, err := analyzer.GetLibraries(actualFiles)
		require.NoError(t, err)
		assert.Equal(t, tc.expectedLibraries, actualLibs, tc.name)

		// check Cache
		actualCachedFiles, _ := ioutil.ReadDir(d + "/fanal/")
		require.Equal(t, 1, len(actualCachedFiles), tc.name)

		// check Cache contents
		var actualCacheValue []byte
		found, err := c.Get("imagebucket", tc.imageFile, &actualCacheValue)
		require.NoError(t, err)
		assert.True(t, found)
		assert.NotEmpty(t, actualCacheValue, tc.name)

		// clear Cache
		require.NoError(t, c.Clear(), tc.name)

		// remove Image
		_, err = cli.ImageRemove(ctx, tc.imageFile, dtypes.ImageRemoveOptions{
			Force:         true,
			PruneChildren: true,
		})
		assert.NoError(t, err, tc.name)
	}
}
