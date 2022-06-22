package dpkg

import (
	"context"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/pkg/dpkg"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/handler"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	handler.RegisterPostHandlerInit(types.DpkgLicensePostHandler, newDpkgLicensePostHandler)
}

const version = 1

type dpkgLicensePostHandler struct{}

func newDpkgLicensePostHandler(artifact.Option) (handler.PostHandler, error) {
	return dpkgLicensePostHandler{}, nil
}

// Handle adds licenses to dpkg files
func (h dpkgLicensePostHandler) Handle(_ context.Context, _ *analyzer.AnalysisResult, blob *types.BlobInfo) error {
	licenses := map[string]string{}
	for _, resource := range blob.CustomResources {
		if resource.Type == dpkg.LicenseAdder {
			licenses[resource.FilePath] = resource.Data.(string)
		}

	}

	var infos []types.PackageInfo
	for _, pkgInfo := range blob.PackageInfos {

		for i, pkg := range pkgInfo.Packages {
			license, ok := licenses[pkg.Name]
			if ok {
				pkgInfo.Packages[i].License = license
			}
		}
		infos = append(infos, pkgInfo)
	}

	blob.PackageInfos = infos
	return nil
}

func (h dpkgLicensePostHandler) Version() int {
	return version
}

func (h dpkgLicensePostHandler) Type() types.HandlerType {
	return types.DpkgLicensePostHandler
}

func (h dpkgLicensePostHandler) Priority() int {
	return types.DpkgLicensePostHandlerPriority
}
