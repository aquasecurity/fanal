package language

import (
	"io"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

type Parser func(r io.Reader) ([]godeptypes.Library, []godeptypes.Dependency, error)
type Identifier func(pkgName, version string) string

func Analyze(fileType, filePath string, r io.Reader, parse Parser, id Identifier) (*analyzer.AnalysisResult, error) {
	parsedLibs, parsedDependencies, err := parse(r)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse %s: %w", filePath, err)
	}

	if len(parsedLibs) == 0 {
		return nil, nil
	}

	// The file path of each library should be empty in case of lock files since they all will the same path.
	return ToAnalysisResult(fileType, filePath, "", parsedLibs, parsedDependencies, id), nil
}

func ToAnalysisResult(fileType, filePath, libFilePath string, libs []godeptypes.Library, deps []godeptypes.Dependency, id Identifier) *analyzer.AnalysisResult {
	if id == nil {
		id = func(pkgName, version string) string {
			return ""
		}
	}

	var pkgs []types.Package
	for _, lib := range libs {
		pkgs = append(pkgs, types.Package{
			Id:       id(lib.Name, lib.Version),
			Name:     lib.Name,
			Version:  lib.Version,
			FilePath: libFilePath,
			Indirect: lib.Indirect,
			License:  lib.License,
		})
	}
	apps := []types.Application{{
		Type:         fileType,
		FilePath:     filePath,
		Libraries:    pkgs,
		Dependencies: deps,
	}}

	return &analyzer.AnalysisResult{Applications: apps}
}
