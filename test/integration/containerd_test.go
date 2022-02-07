//go:build integration
// +build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/fanal/image/daemon"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"
)

const (
	redisImageName = "index.docker.io/library/redis:latest"
	mysqlImageName = "index.docker.io/library/mysql:latest"
)

func TestGetLocalContainerdImage(t *testing.T) {
	ctx := context.Background()

	ctx = namespaces.WithNamespace(ctx, "default")
	normalPath, err := filepath.Abs(".")
	require.NoError(t, err)
	targetPath := filepath.Join(normalPath, "test")
	defer os.RemoveAll(targetPath)
	err = os.Mkdir(targetPath, os.ModePerm)
	require.NoError(t, err)
	_ = t.TempDir()
	req := testcontainers.ContainerRequest{
		Name:       "containerd",
		Image:      "docker.io/geyingqi/dockercontainerd:alpine",
		Entrypoint: []string{"/bin/sh", "-c", "mkdir -p /etc/containerd/ && /usr/local/bin/containerd config default > /etc/containerd/config.toml && /usr/local/bin/containerd -c /etc/containerd/config.toml"},
		Networks:   []string{"host"},
		BindMounts: map[string]string{
			targetPath: "/run/containerd",
		},
		Privileged: true,
	}
	containerdC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	defer containerdC.Terminate(ctx)

	cli, err := containerd.New(targetPath + "/containerd.sock")
	require.NoError(t, err)
	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)

	for _, imgRef := range []string{redisImageName, mysqlImageName} {
		_, err = cli.Pull(ctx, imgRef)
		assert.NoError(t, err)
		cd, err := daemon.NewContainerd(targetPath+"/containerd.sock", imgRef, ctx)
		require.NoError(t, err)
		ref, err := name.ParseReference(imgRef, nameOpts...)
		require.NoError(t, err)
		_, _, err = daemon.ContainerdImage(cd, ref, ctx)
		require.NoError(t, err)
	}
	cli.Close()
}
