package remote

import (
	"io/ioutil"
	"net/url"
	"os"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/artifact/local"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/remote"
)

func NewArtifact(remoteOpts remote.Remote, c cache.ArtifactCache, disabled []analyzer.Type) (artifact.Artifact, func(), error) {
	cleanup := func() {}
	u, err := newURL(remoteOpts.CloneOpts.URL)
	if err != nil {
		return nil, cleanup, err
	}
	remoteOpts.CloneOpts.URL = u

	tmpDir, err := ioutil.TempDir(remoteOpts.ParentDirectory, "fanal-remote")
	if err != nil {
		return nil, cleanup, err
	}
	cleanup = func() {
		_ = os.RemoveAll(tmpDir)
	}

	repo, err := git.PlainClone(tmpDir, remoteOpts.IsBare, remoteOpts.CloneOpts)
	if err != nil {
		return nil, cleanup, err
	}

	if remoteOpts.Commit != "" {
		tree, err := repo.Worktree()
		if err != nil {
			return nil, cleanup, err
		}
		err = tree.Checkout(&git.CheckoutOptions{
			Hash: plumbing.NewHash(remoteOpts.Commit),
		})
		if err != nil {
			return nil, cleanup, err
		}
	}

	// JAR/WAR/EAR doesn't need to be analyzed in git repositories.
	disabled = append(disabled, analyzer.TypeJar)

	return local.NewArtifact(tmpDir, c, disabled), cleanup, nil
}

func newURL(rawurl string) (string, error) {
	u, err := url.Parse(rawurl) // fails on ssh urls
	if err == nil {
		// "https://" can be omitted
		// e.g. github.com/aquasecurity/fanal
		if u.Scheme == "" {
			u.Scheme = "https"
		}
		rawurl = u.String()
	} else {
		u, err := transport.NewEndpoint(rawurl) // defaults to file://
		if err != nil {
			return "", err
		}
		rawurl = u.String() // ssh or file url
	}
	return rawurl, nil
}
