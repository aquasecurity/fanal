package repo

import (
	"bufio"
	"context"
	"github.com/Masterminds/semver"
	"github.com/aquasecurity/fanal/types"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"
	"os"
	"regexp"

	"github.com/aquasecurity/fanal/analyzer"
)

func init() {
	analyzer.RegisterAnalyzer(&apkRepoAnalyzer{})
}

const version = 1

var (
	requiredFiles  = []string{"etc/apk/repositories"}
	urlParseRegexp = regexp.MustCompile(`(https*|ftp)://[0-9A-Za-z.-]+/([A-Za-z]+)/v*([0-9A-Za-z_.-]+)/`)
)

type apkRepoAnalyzer struct{}

func (a apkRepoAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	osFamily := ""
	maxRepoVer := ""
	for scanner.Scan() {
		line := scanner.Text()

		version := urlParseRegexp.FindStringSubmatch(line)
		if len(version) == 4 {

			newOSFamily := version[2]
			newVersion := version[3]

			// Find OS Family
			if osFamily != "" && osFamily != newOSFamily {
				return nil, xerrors.Errorf("repo/apk: unable to get OS Family from repository. Links have different values: %s != %s", osFamily, newOSFamily)
			} else {
				osFamily = newOSFamily
			}

			// Find max Release version
			switch {
			case maxRepoVer == "":
				maxRepoVer = newVersion
			case maxRepoVer == "edge" || newVersion == "edge":
				maxRepoVer = "edge"
			default:
				semverOld, _ := semver.NewVersion(maxRepoVer)
				semverNew, _ := semver.NewVersion(newVersion)
				if semverOld.LessThan(semverNew) {
					maxRepoVer = newVersion
				}
			}
		}
	}

	if maxRepoVer != "" && osFamily != "" {
		return &analyzer.AnalysisResult{
			Repository: &types.Repository{Family: osFamily, Release: maxRepoVer},
		}, nil
	}

	return nil, xerrors.Errorf("repo/apk: Repository file doesn't contains version number or OS family")
}

func (a apkRepoAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a apkRepoAnalyzer) Type() analyzer.Type {
	return analyzer.TypeApkRepo
}

func (a apkRepoAnalyzer) Version() int {
	return version
}
