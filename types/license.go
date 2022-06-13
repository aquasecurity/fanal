package types

type LicenseFile struct {
	FilePath   string
	Findings   []LicenseFinding
	Layer      Layer  `json:",omitempty"`
	Package    string `json:"package,omitempty"`
	PackageDir string `json:"package_dir,omitempty"`
}

type LicenseFinding struct {
	License                          string  `json:"license"`
	MatchType                        string  `json:"match_type"`
	Confidence                       float64 `json:"match_confidence"`
	StartLine                        int     `json:"start_line"`
	EndLine                          int     `json:"end_line"`
	GoogleLicenseClassificationIndex int     `json:"classification_index"`
	GoogleLicenseClassification      string  `json:"google_license_classification"`
	LicenseLink                      string  `json:"license_link,omitempty"`
}
