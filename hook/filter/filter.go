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

type systemFileFilterHook struct{}

// Hook removes files installed by OS package manager such as yum.
func (h systemFileFilterHook) Hook(blob *types.BlobInfo) error {
	// Collect files installed by OS package manager
	var installedFiles []string
	for _, pkgInfo := range blob.PackageInfos {
		for _, pkg := range pkgInfo.Packages {
			for _, installedFile := range pkg.InstalledFiles {
				installedFiles = append(installedFiles, strings.TrimPrefix(installedFile, "/"))
			}
		}
	}

	var apps []types.Application
	for _, app := range blob.Applications {
		// If the lang-specific package was installed by OS package manager, it should not be taken.
		// Otherwise, the package version will be wrong, then it will lead to false positive.
		if utils.StringInSlice(app.FilePath, installedFiles) {
			continue
		}

		var libs []types.LibraryInfo
		for _, lib := range app.Libraries {
			// If the lang-specific package was installed by OS package manager, it should not be taken.
			// Otherwise, the package version will be wrong, then it will lead to false positive.
			if utils.StringInSlice(lib.FilePath, installedFiles) {
				continue
			}
			libs = append(libs, lib)
		}

		// Overwrite Libraries
		app.Libraries = libs
		apps = append(apps, app)
	}

	// Overwrite Applications
	blob.Applications = apps

	return nil
}

func (h systemFileFilterHook) Version() int {
	return version
}

func (h systemFileFilterHook) Type() hook.Type {
	return hook.SystemFileFilter
}
