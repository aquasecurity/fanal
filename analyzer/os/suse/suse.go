package suse

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&suseOSAnalyzer{})
}

const version = 1

var requiredFiles = []string{
	"usr/lib/os-release",
	"etc/os-release",
}

type suseOSAnalyzer struct{}

func (a suseOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	suseName := ""
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "NAME=\"openSUSE") {
			if strings.Contains(line, "Leap") {
				suseName = aos.OpenSUSELeap
			} else if strings.Contains(line, "Tumbleweed") {
				suseName = aos.OpenSUSETumbleweed
			} else {
				suseName = aos.OpenSUSE
			}
			continue
		}
		if strings.HasPrefix(line, "NAME=\"SLES") {
			suseName = aos.SLES
			continue
		}

		if suseName != "" && strings.HasPrefix(line, "VERSION_ID=") {
			return &analyzer.AnalysisResult{
				OS: &types.OS{
					Family: suseName,
					Name:   strings.TrimSpace(line[12 : len(line)-1]),
				},
			}, nil
		}
	}
	return nil, fmt.Errorf("suse: %w", aos.AnalyzeOSError)
}

func (a suseOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a suseOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeSUSE
}

func (a suseOSAnalyzer) Version() int {
	return version
}
