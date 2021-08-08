package nuget

import (
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/nugetconfig"
	"github.com/aquasecurity/go-dep-parser/pkg/nugetlock"
)

func init() {
	analyzer.RegisterAnalyzer(&nugetLibraryAnalyzer{})
}

const (
	version    = 1
	lockFile   = "packages.lock.json"
	configFile = "packages.config"
)

var requiredFiles = []string{lockFile, configFile}

type nugetLibraryAnalyzer struct{}

func (a nugetLibraryAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	// Default values
	analyzerType := types.NuGetLock
	parser := nugetlock.Parse

	targetFile := filepath.Base(target.FilePath)
	if targetFile == configFile {
		analyzerType = types.NuGetConfig
		parser = nugetconfig.Parse
	}

	res, err := library.Analyze(analyzerType, target.FilePath, target.Content, parser)
	if err != nil {
		return nil, xerrors.Errorf("NuGet analysis error: %w", err)
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
