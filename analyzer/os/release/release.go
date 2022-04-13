package release

import (
	"bufio"
	"context"
	"os"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&osReleaseAnalyzer{})
}

const version = 1

var requiredFiles = []string{"etc/os-release"}

type osReleaseAnalyzer struct{}

func (a osReleaseAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()

		ss := strings.SplitN(line, "=", 2)
		if len(ss) != 2 {
			continue
		}
		key, value := ss[0], strings.TrimSpace(ss[1])

		var id, versionID string
		switch key {
		case "ID":
			id = strings.Trim(value, `"'`)
		case "VERSION_ID":
			versionID = strings.Trim(value, `"'`)
		default:
			continue
		}

		var family string
		switch id {
		case "alpine":
			family = aos.Alpine
		case "opensuse-leap":
			family = aos.OpenSUSELeap
		case "opensuse-tumbleweed":
			family = aos.OpenSUSETumbleweed
		case "sles":
			family = aos.SLES
		case "photon":
			family = aos.Photon
		}

		if family != "" && versionID != "" {
			return &analyzer.AnalysisResult{
				OS: &types.OS{Family: family, Name: versionID},
			}, nil
		}
	}

	return nil, nil
}

func (a osReleaseAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a osReleaseAnalyzer) Type() analyzer.Type {
	return analyzer.TypeOSRelease
}

func (a osReleaseAnalyzer) Version() int {
	return version
}
