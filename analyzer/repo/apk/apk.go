package apk

import (
	"bufio"
	"context"
	"os"
	"regexp"

	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	ver "github.com/aquasecurity/go-version/pkg/version"
)

func init() {
	analyzer.RegisterAnalyzer(&apkRepoAnalyzer{})
}

const version = 1

var (
	requiredFiles  = []string{"etc/apk/repositories"}
	urlParseRegexp = regexp.MustCompile(`(https*|ftp)://[0-9A-Za-z.-]+/([A-Za-z]+)/v?([0-9A-Za-z_.-]+)/`)
)

type apkRepoAnalyzer struct{}

func (a apkRepoAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	var osFamily, repoVer string
	for scanner.Scan() {
		line := scanner.Text()

		m := urlParseRegexp.FindStringSubmatch(line)
		if len(m) != 4 {
			continue
		}

		newOSFamily := m[2]
		newVersion := m[3]

		// Find OS Family
		if osFamily != "" && osFamily != newOSFamily {
			return nil, xerrors.Errorf("mixing different distributions in etc/apk/repositories: %s != %s", osFamily, newOSFamily)
		}
		osFamily = newOSFamily

		// Find max Release version
		switch {
		case repoVer == "":
			repoVer = newVersion
		case repoVer == "edge" || newVersion == "edge":
			repoVer = "edge"
		default:
			oldVer, err := ver.Parse(repoVer)
			if err != nil {
				continue
			}
			newVer, err := ver.Parse(newVersion)
			if err != nil {
				continue
			}

			// Take the maximum version in apk repositories
			if newVer.GreaterThan(oldVer) {
				repoVer = newVersion
			}
		}
	}

	// Currently, we support only Alpine Linux in apk repositories.
	if osFamily != aos.Alpine || repoVer == "" {
		return nil, nil
	}

	return &analyzer.AnalysisResult{
		Repository: &types.Repository{
			Family:  osFamily,
			Release: repoVer,
		},
	}, nil
}

func (a apkRepoAnalyzer) Required(filePath string, _ os.FileInfo, _ analyzer.Opener) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a apkRepoAnalyzer) Type() analyzer.Type {
	return analyzer.TypeApkRepo
}

func (a apkRepoAnalyzer) Version() int {
	return version
}
