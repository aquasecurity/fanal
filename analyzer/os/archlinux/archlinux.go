package archlinux

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

func init() {
	analyzer.RegisterAnalyzer(&archlinuxOSAnalyzer{})
}

const version = 1

var requiredFiles = []string{
	"usr/lib/os-release",
	"etc/os-release",
}

type archlinuxOSAnalyzer struct{}

func (a archlinuxOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "NAME=\"Arch Linux") {
			return &analyzer.AnalysisResult{
				OS: &types.OS{
					Family: aos.Arch,
					Name:   "Arch Linux",
				},
			}, nil
		}
	}
	return nil, xerrors.Errorf("arch: %w", aos.AnalyzeOSError)
}

func (a archlinuxOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a archlinuxOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeArch
}

func (a archlinuxOSAnalyzer) Version() int {
	return version
}
