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

func (a nugetLibraryAnalyzer) Analyze(target analyzer.AnalysisTarget) (res *analyzer.AnalysisResult, err error) {
	switch target.FilePath {
	case nugetlockfile:
		res, err = library.Analyze(types.NuGetLock, target.FilePath, target.Content, nugetlock.Parse)
		if err != nil {
			return nil, xerrors.Errorf("unable to parse packages.lock.json: %w", err)
		}
	case nugetconfigfile:
		res, err = library.Analyze(types.NuGetConfig, target.FilePath, target.Content, nugetconfig.Parse)
		if err != nil {
			return nil, xerrors.Errorf("unable to parse packages.config: %w", err)
		}
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
