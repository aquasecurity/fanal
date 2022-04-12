package alpine

import (
	"bufio"
	"context"
	"github.com/Masterminds/semver"
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
	osVersion := ""
	priority := 0
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasSuffix(input.FilePath, alpineReleaseFile) { // get Alpine version from etc/alpine-release file
			osVersion = line
			priority = 2 // alpine-release file has more high priority
		}

		version := apkRepositoriesRegexp.FindStringSubmatch(line) // get Alpine version from etc/apk/repositories file
		if len(version) == 2 {
			newVersion := version[1]
			switch {
			case osVersion == "":
				osVersion = newVersion
				priority = 1
			case osVersion == "edge" || version[1] == "edge":
				osVersion = "edge"
			default:
				semverOld, _ := semver.NewVersion(osVersion)
				semverNew, _ := semver.NewVersion(newVersion)
				if semverOld.LessThan(semverNew) {
					osVersion = newVersion
				}
			}
		}
	}

	if osVersion != "" {
		return &analyzer.AnalysisResult{
			OS: &types.OS{Family: aos.Alpine, Name: osVersion, Priority: priority},
		}, nil
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
