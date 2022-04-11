package dpkg

import (
	"github.com/aquasecurity/fanal/analyzer/pkg/dpkg"
	"github.com/aquasecurity/fanal/hook"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	hook.RegisterHook(dpkgLicenseHook{})
}

const version = 1

type dpkgLicenseHook struct{}

// Hook add licenses to dpkg files
func (h dpkgLicenseHook) Hook(blob *types.BlobInfo) error {
	licenses := map[string]string{}
	for _, resource := range blob.CustomResources {
		if resource.Type == dpkg.LicenseAdder {
			licenses[resource.FilePath] = resource.Data.(string)
		}

	}

	var infos []types.PackageInfo
	for _, pkgInfo := range blob.PackageInfos {

		var packages []types.Package
		for _, pkg := range pkgInfo.Packages {
			license, ok := licenses[pkg.Name]
			if ok {
				pkg.License = license
			}
			packages = append(packages, pkg)
		}

		pkgInfo.Packages = packages
		infos = append(infos, pkgInfo)
	}

	blob.PackageInfos = infos
	return nil
}

func (h dpkgLicenseHook) Version() int {
	return version
}

func (h dpkgLicenseHook) Type() hook.Type {
	return hook.DpkgLicenseAdder
}
