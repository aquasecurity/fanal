// +build integration

package integration

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/extractor/docker"
	testdocker "github.com/aquasecurity/fanal/integration/docker"
	"github.com/aquasecurity/fanal/types"

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
	_ "github.com/aquasecurity/fanal/analyzer/pkg/rpmcmd"
)

const (
	registryImage    = "registry:2"
	registryPort     = "5443/tcp"
	registryUsername = "testuser"
	registryPassword = "testpassword"
)

func TestTLSRegistry(t *testing.T) {
	ctx := context.Background()

	baseDir, err := filepath.Abs(".")
	require.NoError(t, err)

	req := testcontainers.ContainerRequest{
		Name:         "registry",
		Image:        registryImage,
		ExposedPorts: []string{registryPort},
		Env: map[string]string{
			"REGISTRY_HTTP_ADDR":            "0.0.0.0:5443",
			"REGISTRY_HTTP_TLS_CERTIFICATE": "/certs/cert.pem",
			"REGISTRY_HTTP_TLS_KEY":         "/certs/key.pem",
			"REGISTRY_AUTH":                 "htpasswd",
			"REGISTRY_AUTH_HTPASSWD_PATH":   "/auth/htpasswd",
			"REGISTRY_AUTH_HTPASSWD_REALM":  "Registry Realm",
		},
		BindMounts: map[string]string{
			filepath.Join(baseDir, "data", "registry", "certs"): "/certs",
			filepath.Join(baseDir, "data", "registry", "auth"):  "/auth",
		},
		WaitingFor: wait.ForLog("listening on [::]:5443"),
	}

	registryC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	defer registryC.Terminate(ctx)

	registryURL, err := getRegistryURL(ctx, registryC, registryPort)
	require.NoError(t, err)

	config := testdocker.RegistryConfig{
		URL:      registryURL,
		Username: registryUsername,
		Password: registryPassword,
	}

	testCases := []struct {
		name       string
		imageName  string
		imageFile  string
		option     types.DockerOption
		login      bool
		expectedOS types.OS
		wantErr    bool
	}{
		{
			name:      "happy path",
			imageName: "alpine:3.10",
			imageFile: "testdata/fixtures/alpine-310.tar.gz",
			option: types.DockerOption{
				Timeout:               60 * time.Second,
				UserName:              registryUsername,
				Password:              registryPassword,
				InsecureSkipTLSVerify: true,
			},
			expectedOS: types.OS{Name: "3.10.2", Family: "alpine"},
			wantErr:    false,
		},
		{
			name:      "happy path with docker login",
			imageName: "alpine:3.10",
			imageFile: "testdata/fixtures/alpine-310.tar.gz",
			option: types.DockerOption{
				Timeout:               60 * time.Second,
				InsecureSkipTLSVerify: true,
			},
			login:      true,
			expectedOS: types.OS{Name: "3.10.2", Family: "alpine"},
			// TODO: this should be false, but there is regression now.
			// After replacing containers/image with google/go-containerregistry, it is supposed to pass.
			wantErr: true,
		},
		{
			name:      "sad path: tls verify",
			imageName: "alpine:3.10",
			imageFile: "testdata/fixtures/alpine-310.tar.gz",
			option: types.DockerOption{
				Timeout:  60 * time.Second,
				UserName: registryUsername,
				Password: registryPassword,
			},
			expectedOS: types.OS{Name: "3.10.2", Family: "alpine"},
			wantErr:    true,
		},
		{
			name:      "sad path: no credential",
			imageName: "alpine:3.10",
			imageFile: "testdata/fixtures/alpine-310.tar.gz",
			option: types.DockerOption{
				Timeout:               60 * time.Second,
				InsecureSkipTLSVerify: true,
			},
			expectedOS: types.OS{Name: "3.10.2", Family: "alpine"},
			wantErr:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := testdocker.New()
			require.NoError(t, err)

			// 1. Load a test image from the tar file, tag it and push to the test registry.
			err = d.ReplicateImage(ctx, tc.imageName, tc.imageFile, config)
			require.NoError(t, err)

			if tc.login {
				err = d.Login(ctx, config)
				require.NoError(t, err)

				defer exec.Command("docker", "logout", registryURL.Host).Run()
			}

			// 2. Analyze it
			imageRef := fmt.Sprintf("%s/%s", registryURL.Host, tc.imageName)
			imageDetail, err := analyze(ctx, imageRef, tc.option)
			require.Equal(t, tc.wantErr, err != nil)
			if err != nil {
				return
			}

			assert.Equal(t, &tc.expectedOS, imageDetail.OS)
		})
	}
}

func getRegistryURL(ctx context.Context, registryC testcontainers.Container, exposedPort nat.Port) (*url.URL, error) {
	ip, err := registryC.Host(ctx)
	if err != nil {
		return nil, err
	}

	port, err := registryC.MappedPort(ctx, exposedPort)
	if err != nil {
		return nil, err
	}

	urlStr := fmt.Sprintf("https://%s:%s", ip, port.Port())
	return url.Parse(urlStr)
}

func analyze(ctx context.Context, imageRef string, opt types.DockerOption) (*types.ImageDetail, error) {
	d, err := ioutil.TempDir("", "TestRegistry-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(d)

	c, err := cache.NewFSCache(d)
	if err != nil {
		return nil, err
	}

	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, err
	}
	cli.NegotiateAPIVersion(ctx)

	ext, cleanup, err := docker.NewDockerExtractor(ctx, imageRef, opt)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	ac := analyzer.New(ext, c)
	applier := analyzer.NewApplier(c)

	imageInfo, err := ac.Analyze(ctx)
	if err != nil {
		return nil, err
	}

	imageDetail, err := applier.ApplyLayers(imageInfo.ID, imageInfo.LayerIDs)
	if err != nil {
		return nil, err
	}
	return &imageDetail, nil
}
