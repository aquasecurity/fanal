package redhatbase

import (
	"bufio"
	"context"
	"os"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"

	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"golang.org/x/xerrors"
)

const centosAnalyzerVersion = 1

func init() {
	analyzer.RegisterAnalyzer(&centOSAnalyzer{})
}

type centOSAnalyzer struct{}

func (a centOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return nil, xerrors.New("centos: invalid centos-release")
		}

		switch strings.ToLower(result[1]) {
		case "centos", "centos linux":
			return &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.CentOS, Name: result[2]},
			}, nil
		}
	}

	return nil, xerrors.Errorf("centos: %w", aos.AnalyzeOSError)
}

func (a centOSAnalyzer) Required(filePath string, _ os.FileInfo, _ analyzer.Opener) bool {
	return utils.StringInSlice(filePath, a.requiredFiles())
}

func (a centOSAnalyzer) requiredFiles() []string {
	return []string{"etc/centos-release"}
}

func (a centOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeCentOS
}

func (a centOSAnalyzer) Version() int {
	return centosAnalyzerVersion
}
