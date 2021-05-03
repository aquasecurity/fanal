package remote

import (
	git "github.com/go-git/go-git/v5"
)

type Remote struct {
	ParentDirectory string
	IsBare          bool
	Commit          string
	CloneOpts       *git.CloneOptions
}

func NewGitRemote(parentDirectory string, isBare bool, commit string, cloneOpts *git.CloneOptions) (Remote, error) {
	err := cloneOpts.Validate()
	if err != nil {
		return Remote{}, err
	}
	return Remote{
		ParentDirectory: parentDirectory,
		IsBare:          isBare,
		Commit:          commit,
		CloneOpts:       cloneOpts,
	}, nil
}
