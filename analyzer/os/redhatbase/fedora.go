package redhatbase

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

const fedoraAnalyzerVersion = 1

func init() {
	analyzer.RegisterAnalyzer(&fedoraOSAnalyzer{})
}

type fedoraOSAnalyzer struct{}

func (a fedoraOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return nil, errors.New("cent: Invalid fedora-release")
		}

		switch strings.ToLower(result[1]) {
		case "fedora", "fedora linux":
			return &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Fedora, Name: result[2]},
			}, nil
		}
	}
	return nil, fmt.Errorf("fedora: %w", aos.AnalyzeOSError)
}

func (a fedoraOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, a.requiredFiles())
}

func (a fedoraOSAnalyzer) requiredFiles() []string {
	return []string{
		"etc/fedora-release",
		"usr/lib/fedora-release",
	}
}

func (a fedoraOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeFedora
}

func (a fedoraOSAnalyzer) Version() int {
	return fedoraAnalyzerVersion
}
