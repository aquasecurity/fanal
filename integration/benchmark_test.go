// +build performance

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

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

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/extractor/docker"
	"github.com/aquasecurity/fanal/types"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	dtypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testCase struct {
	name                 string
	imageName            string
	imageFile            string
	expectedFiles        []string
	expectedOS           analyzer.OS
	expectedPkgsFromCmds string
	expectedLibraries    string
}

func runChecksBench(j int, b *testing.B, ac analyzer.Config, ctx context.Context, tc testCase, d string, c cache.Cache) {
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		for i := 0; i <= j; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()

				actualFiles, err := ac.Analyze(ctx, tc.imageFile)
				require.NoError(b, err)
				for file, _ := range actualFiles {
					assert.Contains(b, tc.expectedFiles, file, tc.name)
				}
				assert.Equal(b, len(tc.expectedFiles), len(actualFiles), tc.name)

				// check OS
				osFound, err := analyzer.GetOS(actualFiles)
				require.NoError(b, err)
				assert.Equal(b, tc.expectedOS, osFound, tc.name)

				// check Packages
				actualPkgs, err := analyzer.GetPackages(actualFiles)
				require.NoError(b, err)
				data, _ := ioutil.ReadFile(fmt.Sprintf("testdata/goldens/%s.expectedpackages.golden", strings.ReplaceAll(tc.imageName, "/", "")))
				var expectedPkgs []analyzer.Package
				json.Unmarshal(data, &expectedPkgs)
				assert.ElementsMatch(b, expectedPkgs, actualPkgs, tc.name)

				// check Packges from Commands
				actualPkgsFromCmds, err := analyzer.GetPackagesFromCommands(osFound, actualFiles)
				require.NoError(b, err)
				if tc.expectedPkgsFromCmds != "" {
					data, _ := ioutil.ReadFile(tc.expectedPkgsFromCmds)
					var expectedPkgsFromCmds []analyzer.Package
					json.Unmarshal(data, &expectedPkgsFromCmds)
					assert.ElementsMatch(b, expectedPkgsFromCmds, actualPkgsFromCmds, tc.name)
				} else {
					assert.Equal(b, []analyzer.Package(nil), actualPkgsFromCmds, tc.name)
				}

				// check Libraries
				actualLibs, err := analyzer.GetLibraries(actualFiles)
				data, _ = json.MarshalIndent(actualLibs, "", "  ")
				require.NoError(b, err)
				if tc.expectedLibraries != "" {
					data, _ := ioutil.ReadFile(tc.expectedLibraries)
					var expectedLibraries map[analyzer.FilePath][]godeptypes.Library
					json.Unmarshal(data, &expectedLibraries)
					require.Equal(b, len(expectedLibraries), len(actualLibs), tc.name)
					for l := range expectedLibraries {
						assert.Contains(b, actualLibs, l, tc.name)
					}
				} else {
					assert.Equal(b, map[analyzer.FilePath][]godeptypes.Library{}, actualLibs, tc.name)
				}

				// check Cache
				actualCachedFiles, _ := ioutil.ReadDir(d + "/fanal/")
				require.Equal(b, 1, len(actualCachedFiles), tc.name)

				// check Cache contents
				r := c.Get(tc.imageFile)
				actualCacheValue, err := ioutil.ReadAll(r)
				require.NoError(b, err)
				assert.NotEmpty(b, actualCacheValue, tc.name)
			}(i)
		}
		wg.Wait()
	}
}

func BenchmarkFanal_Library_DockerMode_10(b *testing.B) {
	testCases := []testCase{
		{
			name:          "happy path, alpine:3.10",
			imageName:     "alpine:3.10",
			imageFile:     "testdata/fixtures/alpine-310.tar.gz",
			expectedOS:    analyzer.OS{Name: "3.10.2", Family: "alpine"},
			expectedFiles: []string{"etc/alpine-release", "etc/os-release", "lib/apk/db/installed", "/config"},
		},
		//{
		//	name:          "happy path, amazonlinux:2",
		//	imageName:     "amazonlinux:2",
		//	imageFile:     "testdata/fixtures/amazon-2.tar.gz",
		//	expectedFiles: []string{"etc/system-release", "var/lib/rpm/Packages", "etc/os-release", "/config"},
		//	expectedOS:    analyzer.OS{Name: "2 (Karoo)", Family: "amazon"},
		//},
		//{
		//	name:          "happy path, debian:buster",
		//	imageName:     "debian:buster",
		//	imageFile:     "testdata/fixtures/debian-buster.tar.gz",
		//	expectedFiles: []string{"var/lib/dpkg/status", "etc/debian_version", "etc/os-release", "usr/lib/os-release", "/config"},
		//	expectedOS:    analyzer.OS{Name: "10.1", Family: "debian"},
		//},
		//{
		//	name:          "happy path, photon:1.0",
		//	imageName:     "photon:1.0-20190823",
		//	imageFile:     "testdata/fixtures/photon-10.tar.gz",
		//	expectedFiles: []string{"var/lib/rpm/Packages", "etc/lsb-release", "etc/os-release", "/config", "usr/lib/os-release"},
		//	expectedOS:    analyzer.OS{Name: "1.0", Family: "photon"},
		//},
		//{
		//	name:          "happy path, registry.redhat.io/ubi7",
		//	imageName:     "registry.redhat.io/ubi7",
		//	imageFile:     "testdata/fixtures/ubi-7.tar.gz",
		//	expectedFiles: []string{"etc/redhat-release", "etc/system-release", "/config", "var/lib/rpm/Packages", "etc/os-release"},
		//	expectedOS:    analyzer.OS{Name: "7.7", Family: "redhat"},
		//},
		//{
		//	name:          "happy path, opensuse leap 15.1",
		//	imageName:     "opensuse/leap:latest",
		//	imageFile:     "testdata/fixtures/opensuse-leap-151.tar.gz",
		//	expectedFiles: []string{"usr/lib/os-release", "usr/lib/sysimage/rpm/Packages", "/config", "etc/os-release"},
		//	expectedOS:    analyzer.OS{Name: "15.1", Family: "opensuse.leap"},
		//},
		//{
		//	name:                 "happy path, vulnimage with lock files",
		//	imageName:            "knqyf263/vuln-image:1.2.3",
		//	imageFile:            "testdata/fixtures/vulnimage.tar.gz",
		//	expectedFiles:        []string{"etc/os-release", "node-app/package-lock.json", "python-app/Pipfile.lock", "ruby-app/Gemfile.lock", "rust-app/Cargo.lock", "/config", "etc/alpine-release", "lib/apk/db/installed", "php-app/composer.lock"},
		//	expectedOS:           analyzer.OS{Name: "3.7.1", Family: "alpine"},
		//	expectedLibraries:    "testdata/goldens/knqyf263vuln-image:1.2.3.expectedlibs.golden",
		//	expectedPkgsFromCmds: "testdata/goldens/knqyf263vuln-image:1.2.3.expectedpkgsfromcmds.golden",
		//},
	}

	for _, tc := range testCases {
		tc := tc // save a copy of tc for use in t.Run https://gist.github.com/posener/92a55c4cd441fc5e5e85f27bca008721
		b.Run(tc.name, func(b *testing.B) {
			//b.Parallel()
			ctx := context.Background()
			d, _ := ioutil.TempDir("", "TestFanal_Library_*")
			defer os.RemoveAll(d)
			c := cache.Initialize(d)

			opt := types.DockerOption{
				Timeout:  600 * time.Second,
				SkipPing: true,
			}

			cli, err := client.NewClientWithOpts(client.FromEnv)
			require.NoError(b, err, tc.name)

			// ensure image doesnt already exists
			_, _ = cli.ImageRemove(ctx, tc.imageFile, dtypes.ImageRemoveOptions{
				Force:         true,
				PruneChildren: true,
			})

			testfile, err := os.Open(tc.imageFile)
			require.NoError(b, err)

			// load image into docker engine
			_, err = cli.ImageLoad(ctx, testfile, true)
			require.NoError(b, err, tc.name)

			// tag our image to something unique
			err = cli.ImageTag(ctx, tc.imageName, tc.imageFile)
			require.NoError(b, err, tc.name)

			ext, err := docker.NewDockerExtractor(opt, c)
			require.NoError(b, err, tc.name)
			ac := analyzer.Config{Extractor: ext}

			b.ReportAllocs()
			b.ResetTimer()
			// run tests twice, one without cache and with cache
			for i := 1; i <= 2; i++ {
				runChecksBench(5, b, ac, ctx, tc, d, c)

			}
			b.StopTimer()

			// clear Cache
			require.NoError(b, c.Clear(), tc.name)

			// remove Image
			_, err = cli.ImageRemove(ctx, tc.imageFile, dtypes.ImageRemoveOptions{
				Force:         true,
				PruneChildren: true,
			})
			assert.NoError(b, err, tc.name)
		})
	}
}
