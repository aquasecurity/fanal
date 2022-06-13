package types

type License struct {
	FilePath string
	Findings []LicenseFinding
	Layer    Layer `json:",omitempty"`
}

type LicenseFinding struct {
	License                          string  `json:"license"`
	MatchType                        string  `json:"match_type"`
	Confidence                       float64 `json:"match_confidence"`
	StartLine                        int     `json:"start_line"`
	EndLine                          int     `json:"end_line"`
	GoogleLicenseClassificationIndex int     `json:"classification_index"`
	GoogleLicenseClassification      string  `json:"google_license_classification"`
	Package                          string  `json:"package,omitempty"`
	LicenseLink                      string  `json:"license_link,omitempty"`
}
