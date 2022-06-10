//go:build integration

package integration

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/fanal/artifact"
	aimage "github.com/aquasecurity/fanal/artifact/image"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/image"
	"github.com/aquasecurity/fanal/types"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func loadImageMetaData(fname string) (*types.ImageMetadata, error) {
	b, err := os.ReadFile(fname)
	if err != nil {
		return nil, err
	}

	var r types.ImageMetadata
	err = json.Unmarshal(b, &r)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

func configureTestDataPaths(t *testing.T) (string, string) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("/tmp", "fanal")
	require.NoError(t, err)

	containerdDir := filepath.Join(tmpDir, "containerd")
	err = os.MkdirAll(containerdDir, os.ModePerm)
	require.NoError(t, err)

	socketPath := filepath.Join(containerdDir, "containerd.sock")

	return tmpDir, socketPath
}

func startContainerd(t *testing.T, ctx context.Context, hostPath string) testcontainers.Container {
	t.Helper()
	req := testcontainers.ContainerRequest{
		Name:       "containerd",
		Image:      "ghcr.io/aquasecurity/trivy-test-images/containerd:latest",
		Entrypoint: []string{"/bin/sh", "-c", "/usr/local/bin/containerd"},
		Mounts: testcontainers.Mounts(
			testcontainers.BindMount(hostPath, "/run"),
		),
		SkipReaper: true,
		AutoRemove: false,
		WaitingFor: wait.ForLog("containerd successfully booted"),
	}
	containerdC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	_, err = containerdC.Exec(ctx, []string{"chmod", "666", "/run/containerd/containerd.sock"})
	require.NoError(t, err)

	return containerdC
}

func TestGetLocalContainerdImage(t *testing.T) {
	tests := []struct {
		name       string
		imageName  string
		tarArchive string
		golden     string
	}{
		{
			name:       "alpine 3.10",
			imageName:  "ghcr.io/aquasecurity/trivy-test-images:alpine-310",
			tarArchive: "alpine-310.tar.gz",
			golden:     "testdata/goldens/alpine-3.10-image.json.golden",
		},
		{
			name:       "vulnimage",
			imageName:  "ghcr.io/aquasecurity/trivy-test-images:vulnimage",
			tarArchive: "vulnimage.tar.gz",
			golden:     "testdata/goldens/vuln-image-1.2.3-image.json.golden",
		},
	}
	ctx := namespaces.WithNamespace(context.Background(), "default")

	tmpDir, socketPath := configureTestDataPaths(t)
	defer os.RemoveAll(tmpDir)

	// Set a containerd socket
	t.Setenv("CONTAINERD_ADDRESS", socketPath)

	containerdC := startContainerd(t, ctx, tmpDir)
	defer containerdC.Terminate(ctx)

	client, err := containerd.New(socketPath)
	require.NoError(t, err)
	defer client.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheDir := t.TempDir()
			c, err := cache.NewFSCache(cacheDir)
			require.NoError(t, err)

			defer func() {
				c.Clear()
				c.Close()
			}()

			archive, err := os.Open(path.Join("testdata", "fixtures", tt.tarArchive))
			require.NoError(t, err)

			uncompressedArchive, err := gzip.NewReader(archive)
			require.NoError(t, err)
			defer archive.Close()

			_, err = client.Import(ctx, uncompressedArchive)
			require.NoError(t, err)

			img, cleanup, err := image.NewContainerImage(ctx, tt.imageName, types.DockerOption{})
			require.NoError(t, err)
			defer cleanup()

			ar, err := aimage.NewArtifact(img, c, artifact.Option{})
			require.NoError(t, err)

			ref, err := ar.Inspect(ctx)
			require.NoError(t, err)

			expected, err := loadImageMetaData(tt.golden)
			require.NoError(t, err)
			require.Equal(t, expected, &ref.ImageMetadata)
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
			name:     "remote alpine 3.10",
			imageRef: "ghcr.io/aquasecurity/trivy-test-images:alpine-310",
			golden:   "testdata/goldens/alpine-3.10-image.json.golden",
		},
	}

	ctx := namespaces.WithNamespace(context.Background(), "default")

	tmpDir, socketPath := configureTestDataPaths(t)

	containerdC := startContainerd(t, ctx, tmpDir)
	defer containerdC.Terminate(ctx)

	cli, err := containerd.New(socketPath)
	require.NoError(t, err)
	defer cli.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheDir := t.TempDir()
			c, err := cache.NewFSCache(cacheDir)
			require.NoError(t, err)

			defer func() {
				c.Clear()
				c.Close()
			}()

			_, err = cli.Pull(ctx, tt.imageRef)
			require.NoError(t, err)

			img, cleanup, err := image.NewContainerImage(ctx, tt.imageRef, types.DockerOption{})
			require.NoError(t, err)
			defer cleanup()

			art, err := aimage.NewArtifact(img, c, artifact.Option{})
			require.NoError(t, err)
			require.NotNil(t, art)

			artRef, err := art.Inspect(context.Background())
			require.NoError(t, err)

			expected, err := loadImageMetaData(tt.golden)
			require.NoError(t, err)
			require.Equal(t, expected, &artRef.ImageMetadata)
		})
	}
}
