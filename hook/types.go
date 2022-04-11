package hook

import "github.com/aquasecurity/fanal/analyzer/pkg/dpkg"

type Type string

const (
	PythonPkg Type = "python-pkg"
	PkgJson   Type = "pacakgejson"
	GemSpec   Type = "gemspec"

	SystemFileFilter Type = "system-file-filter"

	DpkgLicenseAdder Type = dpkg.LicenseAdder
)
