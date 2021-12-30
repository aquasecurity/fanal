package google

import (
	"context"
	"fmt"
	"strings"

	"github.com/GoogleCloudPlatform/docker-credential-gcr/config"
	"github.com/GoogleCloudPlatform/docker-credential-gcr/credhelper"
	"github.com/GoogleCloudPlatform/docker-credential-gcr/store"
	"github.com/aquasecurity/fanal/types"
)

type Registry struct {
	Store  store.GCRCredStore
	domain string
}

// Google container registry
const gcrURL = "gcr.io"

// Google artifact registry
const garURL = "docker.pkg.dev"

func (g *Registry) CheckOptions(domain string, d types.DockerOption) error {
	if !strings.HasSuffix(domain, gcrURL) && !strings.HasSuffix(domain, garURL) {
		return fmt.Errorf("Google registry: %w", types.InvalidURLPattern)
	}
	g.domain = domain
	if d.GcpCredPath != "" {
		g.Store = store.NewGCRCredStore(d.GcpCredPath)
	}
	return nil
}

func (g *Registry) GetCredential(ctx context.Context) (username, password string, err error) {
	var credStore store.GCRCredStore
	if g.Store == nil {
		credStore, err = store.DefaultGCRCredStore()
		if err != nil {
			return "", "", fmt.Errorf("failed to get GCRCredStore: %w", err)
		}
	} else {
		credStore = g.Store
	}
	userCfg, err := config.LoadUserConfig()
	if err != nil {
		return "", "", fmt.Errorf("failed to load user config: %w", err)
	}
	helper := credhelper.NewGCRCredentialHelper(credStore, userCfg)
	return helper.Get(g.domain)
}
