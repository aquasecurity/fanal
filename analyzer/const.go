package analyzer

type Type string

const (
	// OS
	TypeAlpine     = Type("alpine")
	TypeAmazon     = Type("amazon")
	TypeDebian     = Type("debian")
	TypePhoton     = Type("photon")
	TypeCentOS     = Type("centos")
	TypeFedora     = Type("fedora")
	TypeOracle     = Type("oracle")
	TypeRedHatBase = Type("redhatbase")
	TypeSUSE       = Type("suse")
	TypeUbuntu     = Type("ubuntu")

	// OS Package
	TypeApk  = Type("apk")
	TypeDpkg = Type("dpkg")
	TypeRpm  = Type("rpm")

	// Programming Language Package
	TypeBundler  = Type("bundler")
	TypeCargo    = Type("cargo")
	TypeComposer = Type("composer")
	TypeJar      = Type("jar")
	TypeNpm      = Type("npm")
	TypeNuget    = Type("nuget")
	TypePipenv   = Type("pipenv")
	TypePoetry   = Type("poetry")
	TypeYarn     = Type("yarn")

	// Config
	TypeApkCommand = Type("apk-command")
)
