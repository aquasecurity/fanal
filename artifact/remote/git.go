package remote

import (
	"io/ioutil"
	"net/url"
	"os"

	"github.com/aquasecurity/fanal/analyzer"

	git "github.com/go-git/go-git/v5"

	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/artifact/local"
	"github.com/aquasecurity/fanal/cache"
)

func NewArtifact(rawurl string, c cache.ArtifactCache, disabled []analyzer.Type) (artifact.Artifact, func(), error) {
	cleanup := func() {}

	u, err := newURL(rawurl)
	if err != nil {
		return nil, cleanup, err
	}

	tmpDir, err := ioutil.TempDir("", "fanal-remote")
	if err != nil {
		return nil, cleanup, err
	}

	_, err = git.PlainClone(tmpDir, false, &git.CloneOptions{
		URL:      u.String(),
		Progress: os.Stdout,
		Depth:    1,
	})
	if err != nil {
		return nil, cleanup, err
	}

	cleanup = func() {
		_ = os.RemoveAll(tmpDir)
	}

	// JAR/WAR/EAR doesn't need to be analyzed in git repositories.
	disabled = append(disabled, analyzer.TypeJar)

	return local.NewArtifact(tmpDir, c, disabled), cleanup, nil
}

func newURL(rawurl string) (*url.URL, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	// "https://" can be omitted
	// e.g. github.com/aquasecurity/fanal
	if u.Scheme == "" {
		u.Scheme = "https"
	}

	return u, nil
}
