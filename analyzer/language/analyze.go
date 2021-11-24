package language

import (
	"bytes"
	"io"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

type Parser func(r io.Reader) ([]godeptypes.Library, error)

func Analyze(fileType, filePath string, content []byte, parse Parser) (*analyzer.AnalysisResult, error) {
	r := bytes.NewReader(content)
	parsedLibs, err := parse(r)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse %s: %w", filePath, err)
	}

	if len(parsedLibs) == 0 {
		return nil, nil
	}

	return ToAnalysisResult(fileType, filePath, parsedLibs), nil
}

func ToAnalysisResult(fileType, filePath string, libs []godeptypes.Library) *analyzer.AnalysisResult {
	var pkgs []types.Package
	for _, lib := range libs {
		pkgs = append(pkgs, types.Package{
			Name:    lib.Name,
			Version: lib.Version,
			License: lib.License,
		})
	}
	apps := []types.Application{{
		Type:      fileType,
		FilePath:  filePath,
		Libraries: pkgs,
	}}

	return &analyzer.AnalysisResult{Applications: apps}
}
