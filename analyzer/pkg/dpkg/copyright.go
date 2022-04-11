package dpkg

import (
	"bufio"
	"bytes"
	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	classifier "github.com/google/licenseclassifier/v2/assets"
	"io"
	"regexp"
	"strings"
)

const LicenseAdder = "dpkg-license-adder"

var (
	cl, _                = classifier.DefaultClassifier()
	copyrightFileRegexp  = regexp.MustCompile(`/?usr/share/doc/([0-9A-Za-z_.-]+)/copyright`)
	commonLicensesRegexp = regexp.MustCompile(`/?usr/share/common-licenses/([0-9A-Za-z_.+-]+[0-9A-Za-z+])`)
)

type License struct {
	Pkg      string
	Licenses string
}

// parseCopyrightFile parses /usr/share/doc/*/copyright files
func parseCopyrightFile(content dio.ReadSeekerAt, filePath string) (*analyzer.AnalysisResult, error) {
	var licenses []string
	var buf bytes.Buffer

	tee := io.TeeReader(content, &buf) // Save stream in buffer for re-read with 'licenseclassifier'
	scanner := bufio.NewScanner(tee)

	for scanner.Scan() {
		line := scanner.Text()

		// "License: *" pattern is used
		if strings.HasPrefix(line, "License:") {
			l := strings.TrimSpace(line[8:])
			if !utils.StringInSlice(l, licenses) {
				licenses = append(licenses, l)
			}
			continue
		}

		// Common license pattern is used
		license := commonLicensesRegexp.FindStringSubmatch(line)
		if len(license) == 2 && !utils.StringInSlice(license[1], licenses) {
			licenses = append(licenses, license[1])
		}
	}

	// Use 'github.com/google/licenseclassifier' for find licenses
	result := cl.Match(buf.Bytes())
	for _, match := range result.Matches {
		if !utils.StringInSlice(match.Name, licenses) {
			licenses = append(licenses, match.Name)
		}
	}

	licensesStr := strings.Join(licenses, ", ")
	if licensesStr == "" {
		licensesStr = "Unknown"
	}

	return &analyzer.AnalysisResult{
		CustomResources: []types.CustomResource{
			{
				Type:     LicenseAdder,
				FilePath: getPkgNameFromLicenseFilePath(filePath),
				Data:     licensesStr,
			},
		},
	}, nil
}

func isLicenseFile(filePath string) bool {
	return copyrightFileRegexp.MatchString(filePath)
}

func getPkgNameFromLicenseFilePath(filePath string) string {
	pkgName := copyrightFileRegexp.FindStringSubmatch(filePath)
	if len(pkgName) == 2 {
		return pkgName[1]
	}
	return ""
}
