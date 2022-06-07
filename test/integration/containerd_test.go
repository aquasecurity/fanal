//go:build integration
// +build integration

package integration

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/fanal/artifact"
	aimage "github.com/aquasecurity/fanal/artifact/image"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/image"
	"github.com/aquasecurity/fanal/image/daemon"
	"github.com/aquasecurity/fanal/types"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type daemonImage struct {
	daemon.Image
	name string
}

func (d daemonImage) Name() string {
	return d.name
}

func (d daemonImage) ID() (string, error) {
	return image.ID(d)
}

func (d daemonImage) LayerIDs() ([]string, error) {
	return image.LayerIDs(d)
}
func loadImageMetaData(fname string) (*types.ImageMetadata, error) {
	b, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	r := &types.ImageMetadata{}

	err = json.Unmarshal(b, r)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func configureTestDataPaths() (normalPath, targetPath, socketPath string, err error) {
	normalPath, err = filepath.Abs(".")
	if err != nil {
		return "", "", "", err
	}
	normalPath = filepath.Join(normalPath, "data", "test")
	targetPath = filepath.Join(normalPath, "containerd")

	err = os.MkdirAll(targetPath, os.ModePerm)

	if err != nil {
		return "", "", "", err
	}

	socketPath = filepath.Join(targetPath, "containerd.sock")

	return normalPath, targetPath, socketPath, nil
}

func startContainerd(ctx context.Context, hostPath string) (testcontainers.Container, error) {
	req := testcontainers.ContainerRequest{
		Name:       "containerd",
		Image:      "ghcr.io/aquasecurity/trivy-test-images/containerd:latest",
		Entrypoint: []string{"/bin/sh", "-c", "mkdir -p /etc/containerd/ && /usr/local/bin/containerd config default > /etc/containerd/config.toml && /usr/local/bin/containerd -c /etc/containerd/config.toml"},
		BindMounts: map[string]string{
			"/run": hostPath,
		},
		SkipReaper: true,
		AutoRemove: true,
		WaitingFor: wait.ForLog("Start streaming server"),
	}
	containerdC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})

	if err != nil {
		return nil, err
	}

	_, err = containerdC.Exec(ctx, []string{"chmod", "666", "/run/containerd/containerd.sock"})

	if err != nil {
		return nil, err
	}

	return containerdC, nil
}

func TestGetLocalContainerdImage(t *testing.T) {
	tests := []struct {
		name       string
		imageName  string
		tarArchive string
		golden     string
	}{
		{
			name:       "alpine 3.1.0",
			imageName:  "docker.io/library/alpine:3.10",
			tarArchive: "alpine-310.tar.gz",
			golden:     "testdata/goldens/alpine-3.10-image.json.golden",
		},
		{
			name:       "vulnimage",
			imageName:  "docker.io/knqyf263/vuln-image:1.2.3",
			tarArchive: "vulnimage.tar.gz",
			golden:     "testdata/goldens/vuln-image-1.2.3-image.json.golden",
		},
	}
	ctx := namespaces.WithNamespace(context.Background(), "default")

	testDataPath, targetPath, socketPath, err := configureTestDataPaths()
	require.NoError(t, err)
	defer os.RemoveAll(testDataPath)

	containerdC, err := startContainerd(ctx, testDataPath)
	require.NoError(t, err)

	defer containerdC.Terminate(ctx)

	cli, err := containerd.New(socketPath)
	require.NoError(t, err)
	defer cli.Close()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c, err := cache.NewFSCache(targetPath)
			require.NoError(t, err)

			defer func() {
				c.Clear()
				c.Close()
			}()

			archive, err := os.Open(path.Join("testdata/fixtures", test.tarArchive))
			require.NoError(t, err)
			uncompressedArchive, err := gzip.NewReader(archive)
			require.NoError(t, err)
			defer archive.Close()
			_, err = cli.Import(ctx, uncompressedArchive)
			require.NoError(t, err)

			ref, err := name.ParseReference(test.imageName, name.Insecure)
			require.NoError(t, err)

			img, _, err := daemon.ContainerdImage(socketPath, test.imageName, ref, ctx)
			require.NoError(t, err)
			require.NotNil(t, img)

			dImg := daemonImage{
				Image: img,
				name:  test.imageName,
			}

			art, err := aimage.NewArtifact(dImg, c, artifact.Option{})
			require.NoError(t, err)
			require.NotNil(t, art)

			artRef, err := art.Inspect(context.Background())
			require.NoError(t, err)
			require.NotNil(t, artRef)

			expected, err := loadImageMetaData(test.golden)
			require.NoError(t, err)
			require.Equal(t, expected, &artRef.ImageMetadata)

		})
	}
}

func TestPullLocalContainerdImage(t *testing.T) {
	tests := []struct {
		name     string
		imageRef string
		golden   string
	}{
		{
			name:     "alpine-3.15 in aqua registry",
			imageRef: "ghcr.io/aquasecurity/trivy-test-images/alpine:3.15",
			golden:   "testdata/goldens/test-alpine-3.15.0-image.json.golden",
		},
	}
	ctx := namespaces.WithNamespace(context.Background(), "default")

	testDataPath, targetPath, socketPath, err := configureTestDataPaths()
	require.NoError(t, err)
	defer os.RemoveAll(testDataPath)

	containerdC, err := startContainerd(ctx, testDataPath)
	require.NoError(t, err)

	defer containerdC.Terminate(ctx)

	cli, err := containerd.New(socketPath)
	require.NoError(t, err)
	defer cli.Close()

	for _, test := range tests {
		c, err := cache.NewFSCache(targetPath)

		require.NoError(t, err)

		defer func() {
			c.Clear()
			c.Close()
		}()

		_, err = cli.Pull(ctx, test.imageRef)
		require.NoError(t, err)

		ref, err := name.ParseReference(test.imageRef, name.Insecure)
		require.NoError(t, err)

		img, _, err := daemon.ContainerdImage(socketPath, test.imageRef, ref, ctx)
		require.NoError(t, err)
		require.NotNil(t, img)

		dImg := daemonImage{
			Image: img,
			name:  test.imageRef,
		}

		art, err := aimage.NewArtifact(dImg, c, artifact.Option{})
		require.NoError(t, err)
		require.NotNil(t, art)

		artRef, err := art.Inspect(context.Background())
		require.NoError(t, err)
		require.NotNil(t, artRef)

		b, err := json.Marshal(artRef)
		require.NoError(t, err)

		t.Log(string(b))

		expected, err := loadImageMetaData(test.golden)
		require.NoError(t, err)
		require.Equal(t, expected, &artRef.ImageMetadata)

	}

}
