package classification

import (
	"io/ioutil"

	"github.com/aquasecurity/fanal/licensing/config"
	"github.com/aquasecurity/fanal/types"
	classifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"
)

type Classifier struct {
	classifier          *classifier.Classifier
	includeHeaders      bool
	confidenceThreshold float64
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
		confidenceThreshold: config.MatchConfidenceThreshold,
		ignoredLicenses:     config.IgnoredLicences,
	}, nil
}

// Classify detects and classifies the licencedFile found in a file
func (c *Classifier) Classify(filepath string) (types.License, error) {
	return c.classifyLicense(filepath, c.includeHeaders)
}

func (c *Classifier) classifyLicense(filepath string, headers bool) (types.License, error) {

	license := types.License{FilePath: filepath}

	contents, err := ioutil.ReadFile(filepath)
	if err != nil {
		return license, xerrors.Errorf("unable to read %q: %v", filepath, err)
	}

	for _, m := range c.classifier.Match(contents).Matches {
		// If not looking for headers, skip them
		if !headers && m.MatchType == "Header" {
			continue
		}

		if m.Confidence > c.confidenceThreshold && !c.licenseIgnored(m.Name) {
			license.Findings = append(license.Findings, types.LicenseFinding{
				MatchType:  m.MatchType,
				Name:       m.Name,
				Variant:    m.Variant,
				Confidence: m.Confidence,
				StartLine:  m.StartLine,
				EndLine:    m.EndLine,
			})
		}
	}

	return license, nil
}

func (c *Classifier) licenseIgnored(licenseName string) bool {
	return slices.Contains(c.ignoredLicenses, licenseName)
}
