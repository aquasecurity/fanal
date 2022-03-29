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
	requiredFiles = []string{
		ubuntuConfFilePath,
		esmConfFilePath,
	}
)

type ubuntuOSAnalyzer struct{}

func (a ubuntuOSAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	// context is used to get version number/ESM status from different files/layers
	contextData := ctx.Value("osVersion")
	if contextData == nil {
		return nil, xerrors.Errorf("ubuntu: %w, context == nil", aos.AnalyzeOSError)
	}
	osVersion := contextData.(*analyzer.VersionOS)

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
			if osVersion.Version == esmVersionSuffix {
				version = fmt.Sprintf("%s-%s", version, esmVersionSuffix)
			}
			osVersion.Version = version
			return &analyzer.AnalysisResult{
				OS: &types.OS{
					Family: aos.Ubuntu,
					Name:   osVersion.Version,
				},
			}, nil
		}

		if input.FilePath == esmConfFilePath { // Check esm config file
			if esmEnabled(line) {
				if osVersion.Version != "" {
					osVersion.Version = fmt.Sprintf("%s-%s", osVersion.Version, esmVersionSuffix)
					return &analyzer.AnalysisResult{
						OS: &types.OS{
							Family: aos.Ubuntu,
							Name:   osVersion.Version,
						},
					}, nil
				} else {
					osVersion.Version = esmVersionSuffix
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
		if s.Name == esmServiceName && s.Status == esmStatusEnabled {
			return true
		}
	}
	return false
}
