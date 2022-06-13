package config

type Config struct {

	// Confidence threshold that the license is correctly matched.
	// eg 0.7 would require a 70% confidence that it's a match
	MatchConfidenceThreshold float64 `yaml:"match_confidence"`

	// SeverityThreshold specifies at what point to alert - default is 4, RESTRICTED
	SeverityThreshold int `yaml:"severity_threshold"`

	// Licenses that can be ignored because they're acceptable or
	// not a concern
	IgnoredLicences []string `yaml:"ignored_licenses"`

	// When scanning files, check the header for licenses
	IncludeHeaders bool `yaml:"include_headers"`
}
