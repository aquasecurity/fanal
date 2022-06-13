package types

type License struct {
	FilePath string
	Findings []LicenseFinding
	Layer    Layer  `json:",omitempty"`
	Package  string `json:"package"`
}

type LicenseFinding struct {
	License               string  `json:"license"`
	MatchType             string  `json:"match_type"`
	Variant               string  `json:"variant"`
	Confidence            float64 `json:"match_confidence"`
	StartLine             int     `json:"start_line"`
	EndLine               int     `json:"end_line"`
	LicenseClassification string  `json:"google_license_classification"`
}
