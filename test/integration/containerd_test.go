//go:build integration
// +build integration

package integration

import (
	"compress/gzip"
	"context"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/fanal/image/daemon"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestGetLocalContainerdImage(t *testing.T) {
	tests := []struct {
		name       string
		imageName  string
		tarArchive string
	}{
		{
			name:       "alpine",
			imageName:  "docker.io/library/alpine:3.10",
			tarArchive: "alpine-310.tar.gz",
		},
		{
			name:       "python",
			imageName:  "docker.io/library/python:3.4-alpine",
			tarArchive: "python_3.4-alpine.tar.gz",
		},
	}
	ctx := context.Background()

	ctx = namespaces.WithNamespace(ctx, "default")
	normalPath, err := filepath.Abs(".")
	require.NoError(t, err)
	hostPath := filepath.Join(normalPath, "data", "test")
	targetPath := filepath.Join(hostPath, "containerd")
	defer os.RemoveAll(hostPath)
	err = os.MkdirAll(targetPath, os.ModePerm)
	require.NoError(t, err)

	req := testcontainers.ContainerRequest{
		Name:       "containerd",
		Image:      "docker.io/geyingqi/dockercontainerd:alpine",
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
	require.NoError(t, err)

	_, err = containerdC.Exec(ctx, []string{"chmod", "666", "/run/containerd/containerd.sock"})
	require.NoError(t, err)

	defer containerdC.Terminate(ctx)

	cli, err := containerd.New(targetPath + "/containerd.sock")
	require.NoError(t, err)
	defer cli.Close()

	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archive, err := os.Open(path.Join("testdata/fixtures", test.tarArchive))
			require.NoError(t, err)
			uncompressedArchive, err := gzip.NewReader(archive)
			require.NoError(t, err)
			defer archive.Close()
			_, err = cli.Import(ctx, uncompressedArchive)
			require.NoError(t, err)

			ref, err := name.ParseReference(test.imageName, nameOpts...)
			require.NoError(t, err)
			t.Logf("Identifier: %s, Name: %s\n", ref.Identifier(), ref.Name())

			img, _, err := daemon.ContainerdImage(targetPath+"/containerd.sock", test.imageName, ref, ctx)
			require.NoError(t, err)
			require.NotNil(t, img)
		})
	}
}
