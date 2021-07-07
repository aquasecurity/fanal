package nuget

import (
	"os"
	"path/filepath"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/nugetconfig"
	"github.com/aquasecurity/go-dep-parser/pkg/nugetlock"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&nugetLibraryAnalyzer{})
}

const (
	version         = 1
	nugetlockfile   = "packages.lock.json"
	nugetconfigfile = "packages.config"
)

var requiredFiles = []string{nugetlockfile, nugetconfigfile}

type nugetLibraryAnalyzer struct{}

func (a nugetLibraryAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	targetFile := filepath.Base(target.FilePath)
	var analyzerType string
	var parser library.Parser
	switch targetFile {
	case nugetconfigfile:
		analyzerType = types.NuGetConfig
		parser = nugetconfig.Parse
	default:
		analyzerType = types.NuGetLock
		parser = nugetlock.Parse
	}
	res, err := library.Analyze(analyzerType, target.FilePath, target.Content, parser)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse NuGet file: %w", err)
	}
	return res, nil
}

func (a nugetLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a nugetLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeNuget
}

func (a nugetLibraryAnalyzer) Version() int {
	return version
}
