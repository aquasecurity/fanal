package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	// asMSIEndpointEnv is the environment variable used to store the endpoint on App Service and Functions
	msiEndpointEnv = "MSI_ENDPOINT"

	// the format for expires_on in UTC without AM/PM
	expiresOnDateFormat = "1/2/2006 15:04:05 +00:00"
)

func newTokenJSON(expiresIn string, expiresOn time.Time, resource string) string {
	return fmt.Sprintf(`{
		"access_token" : "accessToken",
		"expires_in"   : %s,
		"expires_on"   : "%s",
		"not_before"   : "%s",
		"resource"     : "%s",
		"token_type"   : "Bearer",
		"refresh_token": "FANAL123"
		}`,
		expiresIn, expiresOn.Format(expiresOnDateFormat), timeToDuration(expiresOn), resource)
}

func timeToDuration(t time.Time) json.Number {
	dur := t.Sub(time.Now().UTC())
	return json.Number(strconv.FormatInt(int64(dur.Round(time.Second).Seconds()), 10))
}

func tokenHandle(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.Header().Add("Content-Type", "application/json")

	expiresOn := time.Now().UTC().Add(time.Hour)
	w.Write([]byte(newTokenJSON("3600", expiresOn, "test")))
}
func TestAzureTokenMSI(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	mux.HandleFunc("/metadata/identity/oauth2/token", tokenHandle)
	mux.HandleFunc("/oauth2/exchange", tokenHandle)

	os.Setenv(msiEndpointEnv, fmt.Sprintf("%s/metadata/identity/oauth2/token", server.URL))
	defer os.Unsetenv(msiEndpointEnv)

	aa, err := NewACRCredStore(context.TODO())
	aa.exchangeScheme = "http"

	assert.Empty(t, err)
	assert.NotEmpty(t, aa)

	token, err := aa.Get(strings.Replace(server.URL, "http://", "", -1))

	assert.Empty(t, err)
	assert.Equal(t, *token, "FANAL123")
}

func TestAzureTokenCredentials(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	mux.HandleFunc("/oauth2/exchange", tokenHandle)
	mux.HandleFunc("/oauth2/token", tokenHandle)

	os.Setenv("AZURE_CLIENT_SECRET", "Test")
	os.Setenv("AZURE_CLIENT_ID", "Test")
	defer func() {
		os.Unsetenv("AZURE_CLIENT_ID")
		os.Unsetenv("AZURE_CLIENT_SECRET")
	}()

	aa, err := NewACRCredStore(context.TODO())

	aa.SetExchangeScheme("http")
	aa.SetActiveDirectoryEndpoint(server.URL)

	assert.Empty(t, err)
	assert.NotEmpty(t, aa)

	token, err := aa.Get(strings.Replace(server.URL, "http://", "", -1))

	if assert.Empty(t, err) {
		assert.Equal(t, *token, "FANAL123")
	}
}

func TestAzureTokenCredentialsError(t *testing.T) {
	os.Setenv("AZURE_CLIENT_SECRET", "Test")

	defer func() {
		os.Unsetenv("AZURE_CLIENT_ID")
		os.Unsetenv("AZURE_CLIENT_SECRET")
	}()

	aa, err := NewACRCredStore(context.TODO())
	assert.Empty(t, err)
	_, err = aa.Get("")
	assert.Error(t, err)
}
