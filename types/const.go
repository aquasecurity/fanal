package types

const (
	ArtifactJSONSchemaVersion = 1
	BlobJSONSchemaVersion     = 1
)

const (
	// Programming language dependencies
	Bundler  = "bundler"
	Cargo    = "cargo"
	Composer = "composer"
	Npm      = "npm"
	NuGet    = "nuget"
	Pipenv   = "pipenv"
	Poetry   = "poetry"
	Yarn     = "yarn"
	Jar      = "jar"

	// Config files
	YAML           = "yaml"
	JSON           = "json"
	TOML           = "toml"
	Dockerfile     = "dockerfile"
	HCL            = "hcl"
	Kubernetes     = "kubernetes"
	CloudFormation = "cloudformation"
	Ansible        = "ansible"
)
