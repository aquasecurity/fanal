package alpine

import (
	"bufio"
	"context"
	"os"
	"regexp"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&alpineOSAnalyzer{})
}

const (
	version             = 1
	alpineReleaseFile   = "etc/alpine-release"
	apkRepositoriesFile = "etc/apk/repositories"
)

var (
	requiredFiles = []string{
		alpineReleaseFile,
		apkRepositoriesFile,
	}

	apkRepositoriesRegexp = regexp.MustCompile("/alpine/v*([0-9A-Za-z_.-]+)/")
)

type alpineOSAnalyzer struct{}

func (a alpineOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasSuffix(input.FilePath, alpineReleaseFile) { // get Alpine version from etc/alpine-release file
			return &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Alpine, Name: line},
			}, nil
		}

		version := apkRepositoriesRegexp.FindStringSubmatch(line) // get Alpine version from etc/apk/repositories file
		if len(version) == 2 {
			return &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Alpine, Name: version[1]},
			}, nil
		}
	}
	return nil, xerrors.Errorf("alpine: %w", aos.AnalyzeOSError)
}

func (a alpineOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a alpineOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeAlpine
}

func (a alpineOSAnalyzer) Version() int {
	return version
}
