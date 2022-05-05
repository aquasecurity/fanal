package nodejs

import (
	"strings"

	"github.com/aquasecurity/fanal/hook"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

func init() {
	hook.RegisterHook(systemFileFilterHook{})
}

const version = 1

var (
	defaultSystemFiles = []string{
		// TODO: Google Distroless removes /var/lib/dpkg/info/*.list, so we cannot know which files are installed by dpkg.
		//       We have to hardcode these files at the moment, but should look for the better way.
		"/usr/lib/python2.7/argparse.egg-info",
		"/usr/lib/python2.7/lib-dynload/Python-2.7.egg-info",
		"/usr/lib/python2.7/wsgiref.egg-info",
	}

	affectedTypes = []string{
		// ruby
		types.GemSpec,

		// python
		types.PythonPkg,

		// node.js
		types.NodePkg,

		// Go binaries
		types.GoBinary,
	}
)

type systemFileFilterHook struct{}

// Hook removes files installed by OS package manager such as yum.
func (h systemFileFilterHook) Hook(blob *types.BlobInfo) error {
	var systemFiles []string
	for _, file := range append(blob.SystemFiles, defaultSystemFiles...) {
		// Trim leading slashes to be the same format as the path in container images.
		systemFile := strings.TrimPrefix(file, "/")
		// We should check the root filepath ("/") and ignore it.
		// Otherwise libraries with an empty filePath will be removed.
		if systemFile != "" {
			systemFiles = append(systemFiles, systemFile)
		}
	}

	var apps []types.Application
	for _, app := range blob.Applications {
		// If the lang-specific package was installed by OS package manager, it should not be taken.
		// Otherwise, the package version will be wrong, then it will lead to false positive.
		if utils.StringInSlice(app.FilePath, systemFiles) && utils.StringInSlice(app.Type, affectedTypes) {
			continue
		}

		var pkgs []types.Package
		for _, lib := range app.Libraries {
			// If the lang-specific package was installed by OS package manager, it should not be taken.
			// Otherwise, the package version will be wrong, then it will lead to false positive.
			if utils.StringInSlice(lib.FilePath, systemFiles) {
				continue
			}
			pkgs = append(pkgs, lib)
		}

		// Overwrite Libraries
		app.Libraries = pkgs
		apps = append(apps, app)
	}

	// Iterate and delete unnecessary customResource
	i := 0
	for _, res := range blob.CustomResources {
		if utils.StringInSlice(res.FilePath, systemFiles) {
			continue
		}
		blob.CustomResources[i] = res
		i++
	}
	blob.CustomResources = blob.CustomResources[:i]

	// Overwrite Applications
	blob.Applications = apps

	// Remove system files since this field is necessary only in this hook.
	blob.SystemFiles = nil

	return nil
}

func (h systemFileFilterHook) Version() int {
	return version
}

func (h systemFileFilterHook) Type() hook.Type {
	return hook.SystemFileFilter
}
