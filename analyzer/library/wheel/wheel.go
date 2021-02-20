package wheel

import (
	"os"
	"strings"

	"github.com/aquasecurity/go-dep-parser/pkg/wheel"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
)

func init() {
	analyzer.RegisterAnalyzer(&wheelLibraryAnalyzer{})
}

const requiredFile = ".dist-info/METADATA"

type wheelLibraryAnalyzer struct{}

func (a wheelLibraryAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	res, err := library.Analyze(library.Wheel, target.FilePath, target.Content, wheel.Parse)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse METADATA: %w", err)
	}
	return res, nil
}

func (a wheelLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return strings.HasSuffix(filePath, requiredFile)
}

func (a wheelLibraryAnalyzer) Name() string {
	return library.Wheel
}
