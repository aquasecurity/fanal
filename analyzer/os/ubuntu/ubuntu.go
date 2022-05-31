package ubuntu

import (
	"bufio"
	"context"
	"os"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&ubuntuOSAnalyzer{})
}

const version = 1

var requiredFiles = []string{"etc/lsb-release"}

type ubuntuOSAnalyzer struct{}

func (a ubuntuOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	isUbuntu := false
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "DISTRIB_ID=Ubuntu" {
			isUbuntu = true
			continue
		}

		if isUbuntu && strings.HasPrefix(line, "DISTRIB_RELEASE=") {
			return &analyzer.AnalysisResult{
				OS: &types.OS{
					Family: aos.Ubuntu,
					Name:   strings.TrimSpace(line[16:]),
				},
			}, nil
		}
	}
	return nil, xerrors.Errorf("ubuntu: %w", aos.AnalyzeOSError)
}

func (a ubuntuOSAnalyzer) Required(filePath string, _ os.FileInfo, _ analyzer.Opener) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a ubuntuOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeUbuntu
}

func (a ubuntuOSAnalyzer) Version() int {
	return version
}
