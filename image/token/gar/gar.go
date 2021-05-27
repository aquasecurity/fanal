package gar

import (
	"context"
	"strings"

	"github.com/aquasecurity/fanal/types"

	"golang.org/x/xerrors"

	"github.com/GoogleCloudPlatform/docker-credential-gcr/config"
	"github.com/GoogleCloudPlatform/docker-credential-gcr/credhelper"
	"github.com/GoogleCloudPlatform/docker-credential-gcr/store"
)

type GAR struct {
	Store  store.GCRCredStore
	domain string
}

// Google artifact repository
const garURL = "docker.pkg.dev"

func (g *GAR) CheckOptions(domain string, d types.DockerOption) error {
	if !strings.HasSuffix(domain, garURL) {
		return xerrors.Errorf("GAR : %w", types.InvalidURLPattern)
	}
	g.domain = domain
	if d.GcpCredPath != "" {
		g.Store = store.NewGCRCredStore(d.GcpCredPath)
	}
	return nil
}

func (g *GAR) GetCredential(ctx context.Context) (username, password string, err error) {
	var credStore store.GCRCredStore
	if g.Store == nil {
		credStore, err = store.DefaultGCRCredStore()
		if err != nil {
			return "", "", xerrors.Errorf("failed to get GCRCredStore: %w", err)
		}
	} else {
		credStore = g.Store
	}
	userCfg, err := config.LoadUserConfig()
	if err != nil {
		return "", "", xerrors.Errorf("failed to load user config: %w", err)
	}
	helper := credhelper.NewGCRCredentialHelper(credStore, userCfg)
	return helper.Get(g.domain)
}
