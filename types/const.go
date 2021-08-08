package types

const (
	ArtifactJSONSchemaVersion = 1
	BlobJSONSchemaVersion     = 1
)

const (
	// Programming language dependencies
	Bundler     = "bundler"
	Cargo       = "cargo"
	Composer    = "composer"
	Npm         = "npm"
	NuGetLock   = "nugetlock"
	NuGetConfig = "nugetconfig"
	Pip         = "pip"
	Pipenv      = "pipenv"
	Poetry      = "poetry"
	Yarn        = "yarn"
	Jar         = "jar"
	GoBinary    = "gobinary"
	GoMod       = "gomod"

	// Config files
	YAML           = "yaml"
	JSON           = "json"
	TOML           = "toml"
	Dockerfile     = "dockerfile"
	HCL            = "hcl"
	Terraform      = "terraform"
	Kubernetes     = "kubernetes"
	CloudFormation = "cloudformation"
	Ansible        = "ansible"
)
