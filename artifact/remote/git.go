package remote

import (
	"io/ioutil"
	"net/url"
	"os"

	"golang.org/x/xerrors"

	git "github.com/go-git/go-git/v5"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/artifact/local"
	"github.com/aquasecurity/fanal/cache"
)

func NewArtifact(rawurl string, c cache.ArtifactCache, artifactOpt artifact.Option, scannerOpt config.ScannerOption) (
	artifact.Artifact, func(), error) {
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
		return nil, cleanup, xerrors.Errorf("git error: %w", err)
	}

	cleanup = func() {
		_ = os.RemoveAll(tmpDir)
	}

	// JAR/WAR/EAR doesn't need to be analyzed in git repositories.
	artifactOpt.DisabledAnalyzers = append(artifactOpt.DisabledAnalyzers, analyzer.TypeJar)

	art, err := local.NewArtifact(tmpDir, c, artifactOpt, scannerOpt)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("fs artifact: %w", err)
	}
	return art, cleanup, nil
}

func newURL(rawurl string) (*url.URL, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, xerrors.Errorf("url parse error: %w", err)
	}
	// "https://" can be omitted
	// e.g. github.com/aquasecurity/fanal
	if u.Scheme == "" {
		u.Scheme = "https"
	}

	return u, nil
}
