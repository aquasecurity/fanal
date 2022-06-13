package classification

import (
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
	severityThreshold   int
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
		severityThreshold:   config.SeverityThreshold,
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
			if severityLevel, severity := c.licenseSeverity(m.Name); severityLevel >= c.severityThreshold {
				license.Findings = append(license.Findings, types.LicenseFinding{
					MatchType:  m.MatchType,
					Name:       m.Name,
					Variant:    m.Variant,
					Confidence: m.Confidence,
					Severity:   severity,
					StartLine:  m.StartLine,
					EndLine:    m.EndLine,
				})
			}
		}
	}

	return license, nil
}

func (c *Classifier) licenseSeverity(licenseName string) (int, string) {
	switch licenseclassifier.LicenseType(licenseName) {
	case "unencumbered":
		return 7, "UNENCUMBERED"
	case "permissive":
		return 6, "PERMISSIVE"
	case "notice":
		return 5, "NOTICE"
	case "reciprocal":
		return 4, "RECIPROCAL"
	case "restricted":
		return 3, "RESTRICTED"
	case "FORBIDDEN":
		return 2, "CRITICAL"
	default:
		return 1, "UNKNOWN"
	}
}

func (c *Classifier) licenseIgnored(licenseName string) bool {
	if c.ignoredLicenses != nil || len(c.ignoredLicenses) > 0 {
		return slices.Contains(c.ignoredLicenses, licenseName)
	}

	return false
}
