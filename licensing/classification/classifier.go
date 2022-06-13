package classification

import (
	"fmt"

	"github.com/aquasecurity/fanal/licensing/config"
	"github.com/aquasecurity/fanal/types"
	"github.com/google/licenseclassifier"
	classifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"
	"golang.org/x/exp/slices"
)

type Classifier struct {
	classifier          *classifier.Classifier
	includeHeaders      bool
	confidenceThreshold float64
	riskThreshold       int
	ignoredLicenses     []string
}

func NewClassifier(config config.Config) (*Classifier, error) {
	_, err := assets.ReadLicenseDir()
	if err != nil {
		return nil, err
	}
	lc, err := assets.DefaultClassifier()
	if err != nil {
		return nil, err
	}
	return &Classifier{
		classifier:          lc,
		includeHeaders:      config.IncludeHeaders,
		riskThreshold:       config.RiskThreshold,
		confidenceThreshold: config.MatchConfidenceThreshold,
		ignoredLicenses:     config.IgnoredLicences,
	}, nil
}

// Classify detects and classifies the licencedFile found in a file
func (c *Classifier) Classify(filePath string, contents []byte) (types.License, error) {
	return c.classifyLicense(filePath, contents, c.includeHeaders)
}

func (c *Classifier) classifyLicense(filePath string, contents []byte, headers bool) (types.License, error) {

	license := types.License{FilePath: filePath}
	for _, m := range c.classifier.Match(contents).Matches {
		// If not looking for headers, skip them
		if !headers && m.MatchType == "Header" {
			continue
		}

		if m.Confidence > c.confidenceThreshold && !c.licenseIgnored(m.Name) {
			if riskLevel, classification := c.googleClassification(m.Name); riskLevel <= c.riskThreshold {
				licenseLink := fmt.Sprintf("https://spdx.org/licenses/%s.html", m.Name)

				license.Findings = append(license.Findings, types.LicenseFinding{
					MatchType:                        m.MatchType,
					License:                          m.Name,
					Confidence:                       m.Confidence,
					GoogleLicenseClassificationIndex: riskLevel,
					GoogleLicenseClassification:      classification,
					StartLine:                        m.StartLine,
					EndLine:                          m.EndLine,
					LicenseLink:                      licenseLink,
				})
			}
		}
	}

	return license, nil
}

func (c *Classifier) googleClassification(licenseName string) (int, string) {
	switch licenseclassifier.LicenseType(licenseName) {
	case "unencumbered":
		return 7, "unencumbered"
	case "permissive":
		return 6, "permissive"
	case "notice":
		return 5, "notice"
	case "reciprocal":
		return 4, "reciprocal"
	case "restricted":
		return 3, "restricted"
	case "FORBIDDEN":
		return 2, "forbidden"
	default:
		return 1, "unknown"
	}
}

func (c *Classifier) licenseIgnored(licenseName string) bool {
	if c.ignoredLicenses != nil || len(c.ignoredLicenses) > 0 {
		return slices.Contains(c.ignoredLicenses, licenseName)
	}

	return false
}
