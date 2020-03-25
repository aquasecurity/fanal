package testutils

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"

	"github.com/docker/docker/api/types/versions"
)

const (
	defaultAPIVersion = "1.38"
	versionMatcher    = "^/v([0-9.]+)"
)

type DockerEngine struct {
	apiVersion string
	images     map[string]string
}

func NewDockerEngine(apiVersion string, imagePaths map[string]string) *httptest.Server {
	de := DockerEngine{
		apiVersion: apiVersion,
		images:     imagePaths,
	}
	ts := httptest.NewServer(de)
	return ts
}

func (d DockerEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	urlPath := r.URL.Path

	re := regexp.MustCompile(versionMatcher)
	matched := re.FindStringSubmatch(urlPath)
	if len(matched) > 1 {
		apiVersion := matched[1]
		urlPath = strings.TrimPrefix(urlPath, matched[0])
		if versions.GreaterThan(apiVersion, d.apiVersion) {
			msg := fmt.Sprintf("client version %s is too new. Maximum supported API version is %s", apiVersion, d.apiVersion)
			http.Error(w, msg, http.StatusBadRequest)
		}
	}

	switch urlPath {
	case "/images/get":
		// Support only 1 image here
		imageName, ok := r.URL.Query()["names"]
		if !ok {
			w.WriteHeader(http.StatusOK)
			return
		}

		filePath, ok := d.images[imageName[0]]
		if !ok {
			http.NotFound(w, r)
			return
		}

		r, err := openImage(filePath)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if _, err = io.Copy(w, r); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}
