package alpine

import (
	"bufio"
	"context"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&alpineReleaseOSAnalyzer{})
}

const alpineReleaseVersion = 1

type alpineReleaseOSAnalyzer struct{}

func (a alpineReleaseOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		return &analyzer.AnalysisResult{
			OS: &types.OS{Family: aos.Alpine, Name: line, Priority: 2}, // alpine-release file has more high priority
		}, nil
	}
	return nil, xerrors.Errorf("alpine: %w", aos.AnalyzeOSError)
}

func (a alpineReleaseOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, a.requiredFiles())
}

func (a alpineReleaseOSAnalyzer) requiredFiles() []string {
	return []string{"etc/alpine-release"}
}

func (a alpineReleaseOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeAlpineRelease
}

func (a alpineReleaseOSAnalyzer) Version() int {
	return alpineReleaseVersion
}
