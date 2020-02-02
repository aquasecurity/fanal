package types

import (
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	digest "github.com/opencontainers/go-digest"
)

type FilePath string

type OS struct {
	Family string
	Name   string
}

type Package struct {
	Name       string
	Version    string
	Release    string
	Epoch      int
	Arch       string
	SrcName    string
	SrcVersion string
	SrcRelease string
	SrcEpoch   int
}

type SrcPackage struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	BinaryNames []string `json:"binaryNames"`
}

type PackageInfo struct {
	FilePath string
	Packages []Package
}

type Application struct {
	Type      string
	FilePath  string
	Libraries []godeptypes.Library
}

type LayerInfo struct {
	SchemaVersion int
	OS            *OS           `json:",omitempty"`
	PackageInfos  []PackageInfo `json:",omitempty"`
	Applications  []Application `json:",omitempty"`
	OpaqueDirs    []string      `json:",omitempty"`
	WhiteoutFiles []string      `json:",omitempty"`
}

type ImageInfo struct {
	Name     string // image name or tar file name
	ID       digest.Digest
	LayerIDs []string
}

type ImageDetail struct {
	OS           *OS           `json:",omitempty"`
	Packages     []Package     `json:",omitempty"`
	Applications []Application `json:",omitempty"`
}
