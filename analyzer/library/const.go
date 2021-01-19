package library

const (
	Bundler  = "bundler"
	Cargo    = "cargo"
	Composer = "composer"
	Npm      = "npm"
	NuGet    = "nuget"
	Pipenv   = "pipenv"
	Poetry   = "poetry"
	Yarn     = "yarn"
	Manifest = "pkg-manifest"
)

var (
	IgnoreDirs = []string{"node_modules", "vendor"}
)
