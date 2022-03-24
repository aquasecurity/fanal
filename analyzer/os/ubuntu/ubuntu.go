package ubuntu

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	xerrors "golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&ubuntuOSAnalyzer{})
}

const (
	version            = 1
	ubuntuConfFilePath = "etc/lsb-release"
	esmConfFilePath    = "var/lib/ubuntu-advantage/status.json"
	esmServiceName     = "esm-infra"
	esmStatusEnabled   = "enabled"
	esmVersionSuffix   = "ESM"
)

var (
	osVersion     = ""
	requiredFiles = []string{
		ubuntuConfFilePath,
		esmConfFilePath,
	}
)

type ubuntuOSAnalyzer struct{}

func (a ubuntuOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	isUbuntu := false
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "DISTRIB_ID=Ubuntu" {
			isUbuntu = true
			continue
		}

		if isUbuntu && strings.HasPrefix(line, "DISTRIB_RELEASE=") {
			version := strings.TrimSpace(line[16:])
			if osVersion == esmVersionSuffix {
				version = fmt.Sprintf("%s-%s", version, esmVersionSuffix)
			}
			osVersion = version
			return &analyzer.AnalysisResult{
				OS: &types.OS{
					Family: aos.Ubuntu,
					Name:   osVersion,
				},
			}, nil
		}

		if input.FilePath == esmConfFilePath { // Check esm config file
			if esmEnabled(line) {
				if osVersion != "" {
					osVersion = fmt.Sprintf("%s-%s", osVersion, esmVersionSuffix)
					return &analyzer.AnalysisResult{
						OS: &types.OS{
							Family: aos.Ubuntu,
							Name:   osVersion,
						},
					}, nil
				} else {
					osVersion = esmVersionSuffix
				}
			}
			return nil, nil
		}
	}
	return nil, xerrors.Errorf("ubuntu: %w", aos.AnalyzeOSError)
}

func (a ubuntuOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a ubuntuOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeUbuntu
}

func (a ubuntuOSAnalyzer) Version() int {
	return version
}

type status struct {
	Services []service `json:"services"`
}

type service struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

func esmEnabled(config string) bool {
	st := status{}

	err := json.Unmarshal([]byte(config), &st)
	if err != nil {
		return false
	}

	for _, s := range st.Services { // Find ESM Service
		if s.Name == esmServiceName {
			if s.Status == esmStatusEnabled {
				return true
			}
		}
	}
	return false
}
