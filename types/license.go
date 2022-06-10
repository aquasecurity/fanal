package types

type License struct {
	FilePath string
	Findings []LicenseFinding
	Layer    Layer `json:",omitempty"`
}

type LicenseFinding struct {
	Name       string
	MatchType  string
	Variant    string
	Confidence float64
	StartLine  int
	EndLine    int
}
