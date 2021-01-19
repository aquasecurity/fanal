package buildinfo

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
)

func init() {
	componentRegexp = regexp.MustCompile(componentPattern)
	architectureRegexp = regexp.MustCompile(architecturePattern)

	analyzer.RegisterAnalyzer(&dockerfileAnalyzer{})
}

var (
	componentPattern    = `"?com.redhat.component"?="(.*?)"`
	architecturePattern = `"?architecture"?="(.*?)"`

	componentRegexp, architectureRegexp *regexp.Regexp
)

// For Red Hat products
type dockerfileAnalyzer struct{}

func (a dockerfileAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	res := componentRegexp.FindStringSubmatch(string(target.Content))
	if len(res) < 2 {
		return nil, xerrors.Errorf("unknown Dockerfile format: %s", target.FilePath)
	}
	component := res[1]

	res = architectureRegexp.FindStringSubmatch(string(target.Content))
	if len(res) < 2 {
		return nil, xerrors.Errorf("unknown Dockerfile format: %s", target.FilePath)
	}
	arch := res[1]

	return &analyzer.AnalysisResult{
		BuildInfo: &analyzer.BuildInfo{
			Nvr:  component + "-" + parseVersion(target.FilePath),
			Arch: arch,
		},
	}, nil
}

func (a dockerfileAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	dir, file := filepath.Split(filePath)
	if dir != "root/buildinfo/" {
		return false
	}
	return strings.HasPrefix(file, "Dockerfile")
}

func (a dockerfileAnalyzer) Name() string {
	return "redhat dockerfile"
}

// parseVersion parses version from a file name
func parseVersion(nvr string) (version string) {
	releaseIndex := strings.LastIndex(nvr, "-")
	if releaseIndex < 0 {
		return ""
	}
	versionIndex := strings.LastIndex(nvr[:releaseIndex], "-")
	version = nvr[versionIndex+1:]
	return version
}
