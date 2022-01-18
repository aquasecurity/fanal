package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/profiles/preview/preview/containerregistry/runtime/containerregistry"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure/auth"
)

type ACRCredStore struct {
	settings auth.EnvironmentSettings
}

func NewACRCredStore() (*ACRCredStore, error) {
	settings, err := auth.GetSettingsFromEnvironment()
	if err != nil {
		return nil, err
	}
	return &ACRCredStore{settings: settings}, nil
}

func (a *ACRCredStore) getServicePrincipalToken() (*adal.ServicePrincipalToken, error) {
	//1.Client Credentials
	if c, e := a.settings.GetClientCredentials(); e == nil {
		oAuthConfig, err := adal.NewOAuthConfig(c.AADEndpoint, c.TenantID)
		if err != nil {
			return nil, err
		}
		return adal.NewServicePrincipalToken(*oAuthConfig, c.ClientID, c.ClientSecret, c.Resource)
	}

	//2. Client Certificate
	if _, e := a.settings.GetClientCertificate(); e == nil {
		return nil, fmt.Errorf("authentication method clientCertificate currently unsupported")
	}

	//3. Username Password
	if _, e := a.settings.GetUsernamePassword(); e == nil {
		return nil, fmt.Errorf("authentication method usernamePassword currently unsupported")
	}

	// 4. MSI
	config := a.settings.GetMSI()
	opts := adal.ManagedIdentityOptions{IdentityResourceID: config.ClientID}
	return adal.NewServicePrincipalTokenFromManagedIdentity(a.settings.Environment.ResourceManagerEndpoint, &opts)
}

func (a *ACRCredStore) getRegistryRefreshToken(registry string, sp *adal.ServicePrincipalToken) (*string, error) {
	err := sp.Refresh()
	if err != nil {
		return nil, err
	}
	token := sp.Token()
	repoClient := containerregistry.NewRefreshTokensClient(fmt.Sprintf("https://%s", registry))
	repoClient.Authorizer = autorest.NewBearerAuthorizer(sp)

	tenantID := a.settings.Values[auth.TenantID]

	result, err := repoClient.GetFromExchange(context.Background(), "access_token", registry, tenantID, "", token.AccessToken)
	if err != nil {
		return nil, err
	}
	return result.RefreshToken, nil
}

func (a *ACRCredStore) Get(registry string) (*string, error) {
	sp, err := a.getServicePrincipalToken()
	if err != nil {
		return nil, err
	}
	return a.getRegistryRefreshToken(registry, sp)
}
