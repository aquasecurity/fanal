package dpkgpkglicenses

import (
	"bufio"
	"bytes"
	"os"
	"regexp"
	"strings"

	"github.com/aquasecurity/fanal/types"

	"github.com/aquasecurity/fanal/analyzer"
)

func init() {
	analyzer.RegisterAnalyzer(&debianPkgLicenseAnalyzer{})
}

const version = 1

var (
	DpkgPkgLicensePath = regexp.MustCompile(`usr/share/doc/(.*)/copyright`)

	patterns = []string{`(4-?clause )?"?BSD"? licen[sc]es?`,
		`(Boost Software|mozilla (public)?|MIT) Licen[sc]es?`,
		`(CCPL|BSD|L?GPL)-[0-9a-z.+-]+( Licenses?)?`,
		`Creative Commons( Licenses?)?`,
		`Public Domain( Licenses?)?`,
		`(CCPL|BSD|L?GPL)-[0-9a-z.+-]+( Licenses?)?`}

	licensePatterns = []string{`^License: ([0-9a-z.+-_]+)`,
		`^Licence: ([0-9a-z.+-_]+)`}

	commonPatternsRegs = regexp.MustCompile("(?i)" + `/usr/share/common-licenses/([0-9A-Za-z_.+-]+[0-9A-Za-z+])`)
)

type debianPkgLicenseAnalyzer struct{}

func (a debianPkgLicenseAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(target.Content))
	pkg := a.parseDpkgPkgLicenseInfo(scanner, target.FilePath)

	if pkg.License != "" {
		return &analyzer.AnalysisResult{
			PackageInfos: []types.PackageInfo{
				{
					FilePath: target.FilePath,
					Packages: []types.Package{pkg},
				},
			},
		}, nil
	}
	return nil, nil

}

type void struct {
}

func (a debianPkgLicenseAnalyzer) parseDpkgPkgLicenseInfo(scanner *bufio.Scanner, filePath string) (pkg types.Package) {

	var pattenrsRegs []*regexp.Regexp
	var licensePatternsRegs []*regexp.Regexp

	for _, r := range patterns {
		pattenrsRegs = append(pattenrsRegs, regexp.MustCompile("(?i)"+r))
	}
	for _, r := range licensePatterns {
		licensePatternsRegs = append(licensePatternsRegs, regexp.MustCompile("(?i)"+r))
	}
	var l []string
	var matches = map[string]void{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		for _, p := range pattenrsRegs {
			strs := p.FindAllString(line, 1)
			if len(strs) == 1 {
				matches[trim(strs[0])] = void{}
			}
		}
		for _, p := range licensePatternsRegs {
			strs := p.FindStringSubmatch(line)
			if len(strs) == 2 {
				matches[trim(strs[1])] = void{}
				break
			}
		}
		strs := commonPatternsRegs.FindStringSubmatch(line)
		if len(strs) == 2 {
			matches[trim(strs[1])] = void{}
		}
	}
	for license, _ := range matches {
		l = append(l, license)
	}
	if len(l) > 0 {
		pkg.License = strings.Join(l, ",")

		strs := DpkgPkgLicensePath.FindStringSubmatch(filePath)
		if len(strs) == 2 {
			pkg.Name = strs[1]
		}
	}
	return pkg
}

func trim(s string) string {
	return strings.TrimRight(s, ".")
}
func (a debianPkgLicenseAnalyzer) Required(filePath string, _ os.FileInfo) bool {

	if DpkgPkgLicensePath.MatchString(filePath) {
		return true
	}
	return false
}

func (a debianPkgLicenseAnalyzer) Type() analyzer.Type {
	return analyzer.TypeDpkgPkgLicense
}

func (a debianPkgLicenseAnalyzer) Version() int {
	return version
}
