// +build performance

package integration

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/fanal/analyzer"
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
	"github.com/aquasecurity/fanal/extractor/docker"
	"github.com/aquasecurity/fanal/types"
	dtypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testCase struct {
	name      string
	imageName string
	imageFile string
}

var testCases = []testCase{
	{
		name:      "happy path alpine:3.10",
		imageName: "alpine:3.10",
		imageFile: "testdata/fixtures/alpine-310.tar.gz",
	},
	{
		name:      "happy path amazonlinux:2",
		imageName: "amazonlinux:2",
		imageFile: "testdata/fixtures/amazon-2.tar.gz",
	},
	{
		name:      "happy path debian:buster",
		imageName: "debian:buster",
		imageFile: "testdata/fixtures/debian-buster.tar.gz",
	},
	{
		name:      "happy path photon:1.0",
		imageName: "photon:1.0-20190823",
		imageFile: "testdata/fixtures/photon-10.tar.gz",
	},
	{
		name:      "happy path registry.redhat.io/ubi7",
		imageName: "registry.redhat.io/ubi7",
		imageFile: "testdata/fixtures/ubi-7.tar.gz",
	},
	{
		name:      "happy path opensuse leap 15.1",
		imageName: "opensuse/leap:latest",
		imageFile: "testdata/fixtures/opensuse-leap-151.tar.gz",
	},
	{
		name:      "happy path vulnimage with lock files",
		imageName: "knqyf263/vuln-image:1.2.3",
		imageFile: "testdata/fixtures/vulnimage.tar.gz",
	},
}

func run(b *testing.B, ctx context.Context, imageName string, ac analyzer.Config) {
	actualFiles, err := ac.Analyze(ctx, imageName)
	require.NoError(b, err)

	osFound, err := analyzer.GetOS(actualFiles)
	require.NoError(b, err)

	_, err = analyzer.GetPackages(actualFiles)
	require.NoError(b, err)

	_, err = analyzer.GetPackagesFromCommands(osFound, actualFiles)
	require.NoError(b, err)

	_, err = analyzer.GetLibraries(actualFiles)
	require.NoError(b, err)
}

func runChecksBench(b *testing.B, ctx context.Context, imageName string, ac analyzer.Config, c cache.Cache) {
	for i := 0; i < b.N; i++ {
		run(b, ctx, imageName, ac)
		if c != nil {
			_ = c.Clear()
		}
	}
}

func BenchmarkDockerMode_WithoutCache(b *testing.B) {
	for _, tc := range testCases {
		tc := tc
		b.Run(tc.name, func(b *testing.B) {
			benchCache, err := ioutil.TempDir("", "DockerMode_WithoutCache_")
			require.NoError(b, err)
			defer os.RemoveAll(benchCache)

			ctx, imageName, c, cli, ac := setup(b, tc, benchCache)

			b.ReportAllocs()
			b.ResetTimer()
			runChecksBench(b, ctx, imageName, ac, c)
			b.StopTimer()

			teardown(b, ctx, tc.imageName, imageName, cli)
		})
	}
}

func BenchmarkDockerMode_WithCache(b *testing.B) {
	for _, tc := range testCases {
		tc := tc
		b.Run(tc.name, func(b *testing.B) {
			benchCache, err := ioutil.TempDir("", "DockerMode_WithCache_")
			require.NoError(b, err)
			defer os.RemoveAll(benchCache)

			ctx, imageName, _, cli, ac := setup(b, tc, benchCache)
			// run once to generate cache
			run(b, ctx, imageName, ac)

			b.ReportAllocs()
			b.ResetTimer()
			runChecksBench(b, ctx, imageName, ac, nil)
			b.StopTimer()

			teardown(b, ctx, tc.imageName, imageName, cli)
		})

	}
}

func teardown(b *testing.B, ctx context.Context, originalImageName, imageName string, cli *client.Client) {
	_, err := cli.ImageRemove(ctx, originalImageName, dtypes.ImageRemoveOptions{
		Force:         true,
		PruneChildren: true,
	})
	assert.NoError(b, err)

	_, err = cli.ImageRemove(ctx, imageName, dtypes.ImageRemoveOptions{
		Force:         true,
		PruneChildren: true,
	})
	assert.NoError(b, err)
}

func setup(b *testing.B, tc testCase, cacheDir string) (context.Context, string, cache.Cache, *client.Client, analyzer.Config) {
	ctx := context.Background()
	c := cache.New(cacheDir)

	opt := types.DockerOption{
		Timeout:  600 * time.Second,
		SkipPing: true,
	}

	cli, err := client.NewClientWithOpts(client.FromEnv)
	require.NoError(b, err, tc.name)

	// ensure image doesnt already exists
	_, _ = cli.ImageRemove(ctx, tc.imageName, dtypes.ImageRemoveOptions{
		Force:         true,
		PruneChildren: true,
	})

	testFile, err := os.Open(tc.imageFile)
	require.NoError(b, err)

	// load image into docker engine
	resp, err := cli.ImageLoad(ctx, testFile, false)
	require.NoError(b, err, tc.name)

	// ensure an image has finished being loaded.
	io.Copy(ioutil.Discard, resp.Body)
	require.NoError(b, resp.Body.Close())

	imageName := fmt.Sprintf("%s-%s", tc.imageName, nextRandom())

	// tag our image to something unique
	err = cli.ImageTag(ctx, tc.imageName, imageName)
	require.NoError(b, err, tc.name)

	ext := docker.NewDockerExtractor(opt, c)
	ac := analyzer.Config{Extractor: ext}
	return ctx, imageName, c, cli, ac
}
