// +build integration

package integration

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	_ "github.com/aquasecurity/fanal/analyzer/command/apk"
	"github.com/aquasecurity/fanal/analyzer/config"
	_ "github.com/aquasecurity/fanal/analyzer/library/bundler"
	_ "github.com/aquasecurity/fanal/analyzer/library/cargo"
	_ "github.com/aquasecurity/fanal/analyzer/library/composer"
	_ "github.com/aquasecurity/fanal/analyzer/library/npm"
	_ "github.com/aquasecurity/fanal/analyzer/library/pipenv"
	_ "github.com/aquasecurity/fanal/analyzer/library/poetry"
	_ "github.com/aquasecurity/fanal/analyzer/library/yarn"
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/os/amazonlinux"
	_ "github.com/aquasecurity/fanal/analyzer/os/debian"
	_ "github.com/aquasecurity/fanal/analyzer/os/photon"
	_ "github.com/aquasecurity/fanal/analyzer/os/redhatbase"
	_ "github.com/aquasecurity/fanal/analyzer/os/suse"
	_ "github.com/aquasecurity/fanal/analyzer/os/ubuntu"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/dpkg"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/rpm"
	"github.com/aquasecurity/fanal/applier"
	"github.com/aquasecurity/fanal/artifact"
	aimage "github.com/aquasecurity/fanal/artifact/image"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/image"
	"github.com/aquasecurity/fanal/types"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	dtypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "update golden files")

type testCase struct {
	name                 string
	imageName            string
	remoteImageName      string
	imageFile            string
	expectedOS           types.OS
	expectedPkgsFromCmds string
	expectedLibraries    string
}

var testCases = []testCase{
	{
		name:            "happy path, alpine:3.10",
		imageName:       "alpine:3.10",
		remoteImageName: "knqyf263/alpine:3.10",
		imageFile:       "testdata/fixtures/alpine-310.tar.gz",
		expectedOS:      types.OS{Name: "3.10.2", Family: "alpine"},
	},
	{
		name:            "happy path, amazonlinux:2",
		imageName:       "amazonlinux:2",
		remoteImageName: "knqyf263/amazonlinux:2",
		imageFile:       "testdata/fixtures/amazon-2.tar.gz",
		expectedOS:      types.OS{Name: "2 (Karoo)", Family: "amazon"},
	},
	{
		name:            "happy path, debian:buster",
		imageName:       "debian:buster",
		remoteImageName: "knqyf263/debian:buster",
		imageFile:       "testdata/fixtures/debian-buster.tar.gz",
		expectedOS:      types.OS{Name: "10.1", Family: "debian"},
	},
	{
		name:            "happy path, photon:1.0",
		imageName:       "photon:1.0-20190823",
		remoteImageName: "knqyf263/photon:1.0-20190823",
		imageFile:       "testdata/fixtures/photon-10.tar.gz",
		expectedOS:      types.OS{Name: "1.0", Family: "photon"},
	},
	{
		name:            "happy path, registry.redhat.io/ubi7",
		imageName:       "registry.redhat.io/ubi7",
		remoteImageName: "knqyf263/registry.redhat.io-ubi7:latest",
		imageFile:       "testdata/fixtures/ubi-7.tar.gz",
		expectedOS:      types.OS{Name: "7.7", Family: "redhat"},
	},
	{
		name:            "happy path, opensuse leap 15.1",
		imageName:       "opensuse/leap:latest",
		remoteImageName: "knqyf263/opensuse-leap:latest",
		imageFile:       "testdata/fixtures/opensuse-leap-151.tar.gz",
		expectedOS:      types.OS{Name: "15.1", Family: "opensuse.leap"},
	},
	{
		name:                 "happy path, vulnimage with lock files",
		imageName:            "knqyf263/vuln-image:1.2.3",
		remoteImageName:      "knqyf263/vuln-image:1.2.3",
		imageFile:            "testdata/fixtures/vulnimage.tar.gz",
		expectedOS:           types.OS{Name: "3.7.1", Family: "alpine"},
		expectedLibraries:    "testdata/goldens/vuln-image1.2.3.expectedlibs.golden",
		expectedPkgsFromCmds: "testdata/goldens/vuln-image1.2.3.expectedpkgsfromcmds.golden",
	},
}

func TestFanal_Library_DockerLessMode(t *testing.T) {
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			d, _ := ioutil.TempDir("", "TestFanal_Library_DockerLessMode_*")
			defer os.RemoveAll(d)

			c, err := cache.NewFSCache(d)
			require.NoError(t, err, tc.name)

			opt := types.DockerOption{
				Timeout:  600 * time.Second,
				SkipPing: true,
			}

			cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
			require.NoError(t, err, tc.name)

			// remove existing Image if any
			_, _ = cli.ImageRemove(ctx, tc.remoteImageName, dtypes.ImageRemoveOptions{
				Force:         true,
				PruneChildren: true,
			})

			img, cleanup, err := image.NewDockerImage(ctx, tc.remoteImageName, opt)
			require.NoError(t, err, tc.name)
			defer cleanup()

			ar := aimage.NewArtifact(img, c, nil, config.ScannerOption{})
			applier := applier.NewApplier(c)

			// run tests twice, one without cache and with cache
			for i := 1; i <= 2; i++ {
				runChecks(t, ctx, ar, applier, tc)
			}

			// clear Cache
			require.NoError(t, c.Clear(), tc.name)
		})
	}
}

func TestFanal_Library_DockerMode(t *testing.T) {
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			d, _ := ioutil.TempDir("", "TestFanal_Library_DockerMode_*")
			defer os.RemoveAll(d)
			c, err := cache.NewFSCache(d)
			require.NoError(t, err)
			opt := types.DockerOption{
				Timeout:  600 * time.Second,
				SkipPing: true,
			}

			cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
			require.NoError(t, err, tc.name)

			testfile, err := os.Open(tc.imageFile)
			require.NoError(t, err)

			// load image into docker engine
			resp, err := cli.ImageLoad(ctx, testfile, true)
			require.NoError(t, err, tc.name)
			io.Copy(ioutil.Discard, resp.Body)

			// tag our image to something unique
			err = cli.ImageTag(ctx, tc.imageName, tc.imageFile)
			require.NoError(t, err, tc.name)

			img, cleanup, err := image.NewDockerImage(ctx, tc.imageFile, opt)
			require.NoError(t, err, tc.name)
			defer cleanup()

			ar := aimage.NewArtifact(img, c, nil, config.ScannerOption{})
			applier := applier.NewApplier(c)

			// run tests twice, one without cache and with cache
			for i := 1; i <= 2; i++ {
				runChecks(t, ctx, ar, applier, tc)
			}

			// clear Cache
			require.NoError(t, c.Clear(), tc.name)

			// remove Image
			_, err = cli.ImageRemove(ctx, tc.imageFile, dtypes.ImageRemoveOptions{
				Force:         true,
				PruneChildren: true,
			})
			assert.NoError(t, err, tc.name)
			_, err = cli.ImageRemove(ctx, tc.imageName, dtypes.ImageRemoveOptions{
				Force:         true,
				PruneChildren: true,
			})
			assert.NoError(t, err, tc.name)

			// clear Cache
			require.NoError(t, c.Clear(), tc.name)
		})
	}
}

func TestFanal_Library_TarMode(t *testing.T) {
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			d, _ := ioutil.TempDir("", "TestFanal_Library_TarMode_*")
			defer os.RemoveAll(d)

			c, err := cache.NewFSCache(d)
			require.NoError(t, err)

			img, err := image.NewArchiveImage(tc.imageFile)
			require.NoError(t, err, tc.name)

			ar := aimage.NewArtifact(img, c, nil, config.ScannerOption{})
			applier := applier.NewApplier(c)

			runChecks(t, ctx, ar, applier, tc)

			// clear Cache
			require.NoError(t, c.Clear(), tc.name)
		})
	}
}

func runChecks(t *testing.T, ctx context.Context, ar artifact.Artifact, applier applier.Applier, tc testCase) {
	imageInfo, err := ar.Inspect(ctx)
	require.NoError(t, err, tc.name)
	imageDetail, err := applier.ApplyLayers(imageInfo.ID, imageInfo.BlobIDs)
	require.NoError(t, err, tc.name)
	commonChecks(t, imageDetail, tc)
}

func commonChecks(t *testing.T, detail types.ArtifactDetail, tc testCase) {
	assert.Equal(t, tc.expectedOS, *detail.OS, tc.name)
	checkPackages(t, detail, tc)
	checkPackageFromCommands(t, detail, tc)
	checkLibraries(detail, t, tc)
}

func checkPackages(t *testing.T, detail types.ArtifactDetail, tc testCase) {
	r := strings.NewReplacer("/", "-", ":", "-")
	goldenFile := fmt.Sprintf("testdata/goldens/packages/%s.json.golden", r.Replace(tc.imageName))
	if *update {
		b, err := json.MarshalIndent(detail.Packages, "", "  ")
		require.NoError(t, err)
		err = ioutil.WriteFile(goldenFile, b, 0666)
		require.NoError(t, err)
		return
	}
	data, err := ioutil.ReadFile(goldenFile)
	require.NoError(t, err, tc.name)

	var expectedPkgs []types.Package
	err = json.Unmarshal(data, &expectedPkgs)
	require.NoError(t, err)

	require.Equal(t, len(expectedPkgs), len(detail.Packages), tc.name)
	sort.Slice(expectedPkgs, func(i, j int) bool { return expectedPkgs[i].Name < expectedPkgs[j].Name })
	sort.Slice(detail.Packages, func(i, j int) bool { return detail.Packages[i].Name < detail.Packages[j].Name })

	for i := 0; i < len(expectedPkgs); i++ {
		require.Equal(t, expectedPkgs[i].Name, detail.Packages[i].Name, tc.name)
		require.Equal(t, expectedPkgs[i].Version, detail.Packages[i].Version, tc.name)
	}
}

func checkLibraries(detail types.ArtifactDetail, t *testing.T, tc testCase) {
	if tc.expectedLibraries != "" {
		data, _ := ioutil.ReadFile(tc.expectedLibraries)
		var expectedLibraries map[string][]godeptypes.Library

		err := json.Unmarshal(data, &expectedLibraries)
		require.NoError(t, err)
		require.Equal(t, len(expectedLibraries), len(detail.Applications), tc.name)
	} else {
		assert.Nil(t, detail.Applications, tc.name)
	}
}

func checkPackageFromCommands(t *testing.T, detail types.ArtifactDetail, tc testCase) {
	if tc.expectedPkgsFromCmds != "" {
		data, _ := ioutil.ReadFile(tc.expectedPkgsFromCmds)
		var expectedPkgsFromCmds []types.Package

		err := json.Unmarshal(data, &expectedPkgsFromCmds)
		require.NoError(t, err)
		assert.ElementsMatch(t, expectedPkgsFromCmds, detail.HistoryPackages, tc.name)
	} else {
		assert.Equal(t, []types.Package(nil), detail.HistoryPackages, tc.name)
	}
}
