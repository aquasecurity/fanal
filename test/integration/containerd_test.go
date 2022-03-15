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
	"github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	redisImageName  = "index.docker.io/library/redis:latest"
	mysqlImageName  = "index.docker.io/library/mysql:latest"
	pythonImageName = "index.docker.io/library/python:3.4-alpine"
)

func TestGetLocalContainerdImage(t *testing.T) {
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

	for _, imgRef := range []string{redisImageName, mysqlImageName, pythonImageName} {
		_, err = cli.Pull(ctx, imgRef)
		require.NoError(t, err)

		cd, err := daemon.NewContainerd(targetPath+"/containerd.sock", imgRef, ctx)
		require.NoError(t, err)

		ref, err := name.ParseReference(imgRef, nameOpts...)
		require.NoError(t, err)
		t.Logf("Identifier: %s, Name: %s\n", ref.Identifier(), ref.Name())

		//Identifier: latest, Name: index.docker.io/library/redis:latest
		img, _, err := daemon.ContainerdImage(cd, ref, ctx)
		require.NoError(t, err)
		require.NotNil(t, img)

	}
}
