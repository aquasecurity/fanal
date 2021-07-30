package library

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

type parser func(r io.Reader) ([]godeptypes.Library, error)

func Analyze(analyzerType, filePath string, content []byte, parse parser) (*analyzer.AnalysisResult, error) {
	r := bytes.NewReader(content)
	parsedLibs, err := parse(r)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse %s: %w", filePath, err)
	}

	if len(parsedLibs) == 0 {
		return nil, nil
	}

	return ToAnalysisResult(analyzerType, filePath, parsedLibs), nil
}

func ToAnalysisResult(analyzerType, filePath string, libs []godeptypes.Library) *analyzer.AnalysisResult {
	var libInfos []types.LibraryInfo
	for _, lib := range libs {
		libInfos = append(libInfos, types.LibraryInfo{
			Library: lib,
		})
	}
	apps := []types.Application{{
		Type:      analyzerType,
		FilePath:  filePath,
		Libraries: libInfos,
	}}

	return &analyzer.AnalysisResult{Applications: apps}
}

func ToAnalysisResultExtended(analyzerType, filePath string, libs []godeptypes.EmbeddedLibrary) *analyzer.AnalysisResult {
	filesIdx := make(map[string][]types.LibraryInfo)

	for _, lib := range libs {
		key := strings.Join(lib.ParentDependencies, ",")
		libInfo := types.LibraryInfo{
			Library: godeptypes.Library{Name: lib.Name, Version: lib.Version},
		}
		libInfos, ok := filesIdx[key]
		if !ok {
			libInfos = []types.LibraryInfo{libInfo}
		} else {
			libInfos = append(libInfos, libInfo)
		}
		filesIdx[key] = libInfos
	}

	apps := make([]types.Application, len(filesIdx))

	for key, libs := range filesIdx {
		items := strings.Split(key, ",")
		apps = append(apps, types.Application{
			Type:      analyzerType,
			FilePath:  mergePath(filePath, items),
			Libraries: libs,
		})
	}

	return &analyzer.AnalysisResult{Applications: apps}
}

func mergePath(rootPath string, items []string) string {
	dependencyDelimiter := "-->"
	var s string
	if rootPath == items[0] || strings.HasSuffix(rootPath, items[0]) {
		if len(items) == 1 {
			s = rootPath
		} else {
			s = strings.Join(items, dependencyDelimiter)
		}
	} else {
		s = fmt.Sprintf("%s%s%s", rootPath, dependencyDelimiter, strings.Join(items, "-->"))
	}
	return s
}
