package azure

import (
	"context"
	"strings"

	"github.com/aquasecurity/fanal/types"

	"golang.org/x/xerrors"
)

type Registry struct {
	domain string
}

const azureURL = "azurecr.io"

func (r *Registry) CheckOptions(domain string, d types.DockerOption) error {
	if !strings.HasSuffix(domain, azureURL) {
		return xerrors.Errorf("Azure registry: %w", types.InvalidURLPattern)
	}
	r.domain = domain
	return nil
}

func (r *Registry) GetCredential(ctx context.Context) (username, password string, err error) {
	credStore, err := NewACRCredStore()
	if err != nil {
		return "", "", err
	}
	token, err := credStore.Get(r.domain)
	return "00000000-0000-0000-0000-000000000000", *token, err
}
