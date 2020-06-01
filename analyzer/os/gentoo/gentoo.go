package gentoo

import (
	"bufio"
	"bytes"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&gentooOSAnalyzer{})
}

var requiredFiles = []string{"etc/gentoo-release"}

type gentooOSAnalyzer struct{}

func (a gentooOSAnalyzer) Analyze(content []byte) (analyzer.AnalyzeReturn, error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(content))
	for scanner.Scan() {
		line := scanner.Text()
		return analyzer.AnalyzeReturn{
			OS: types.OS{Family: aos.Gentoo, Name: line},
		}, nil
	}
	return analyzer.AnalyzeReturn{}, xerrors.Errorf("gentoo: %w", aos.AnalyzeOSError)
}

func (a gentooOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a gentooOSAnalyzer) Name() string {
	return aos.Gentoo
}
