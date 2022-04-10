package secret_test

import (
	"io/ioutil"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/secret"
	"github.com/aquasecurity/fanal/types"
)

func TestSecretScanner(t *testing.T) {
	type fields struct {
		Rules         []secret.Rule
		AllowList     secret.AllowList
		ExcludeBlocks secret.ExcludeBlocks
	}

	var basicRule = secret.Rule{
		ID:       "generic",
		Type:     "genericType",
		Severity: "HIGH",
		Title:    "Generic Rule",
		Regex:    regexp.MustCompile(`(?i)(?P<key>(secret))(=|:).{0,5}['"](?P<secret>[0-9a-zA-Z\-_=]{8,64})['"]`),
	}

	tests := []struct {
		name          string
		fields        fields
		inputFilePath string
		want          types.Secret
	}{
		{
			name: "find match",
			fields: fields{
				Rules: []secret.Rule{
					basicRule,
				},
			},
			inputFilePath: "testdata/secret.txt",
			want: types.Secret{
				FilePath: "testdata/secret.txt",
				Findings: []types.SecretFinding{
					{
						RuleID:    basicRule.ID,
						Type:      basicRule.Type,
						Severity:  basicRule.Severity,
						Title:     basicRule.Title,
						StartLine: 2,
						EndLine:   3,
						Match:     "generic secret line *****",
					},
					{
						RuleID:    basicRule.ID,
						Type:      basicRule.Type,
						Severity:  basicRule.Severity,
						Title:     basicRule.Title,
						StartLine: 4,
						EndLine:   5,
						Match:     "*****",
					},
				},
			},
		},
		{
			name: "rule allowlist path",
			fields: fields{
				Rules: []secret.Rule{
					{
						ID:       basicRule.ID,
						Type:     basicRule.Type,
						Severity: basicRule.Severity,
						Title:    basicRule.Title,
						Regex:    basicRule.Regex,
						AllowList: secret.AllowList{
							Title: "Allowlist",
							Paths: []*regexp.Regexp{
								regexp.MustCompile(`test`),
							},
						},
					},
				},
			},
			inputFilePath: "testdata/secret.txt",
			want:          types.Secret{},
		},
		{
			name: "rule allowlist regex",
			fields: fields{
				Rules: []secret.Rule{
					{
						ID:       basicRule.ID,
						Type:     basicRule.Type,
						Severity: basicRule.Severity,
						Title:    basicRule.Title,
						Regex:    basicRule.Regex,
						AllowList: secret.AllowList{
							Title: "Allowlist",
							Regexes: []*regexp.Regexp{
								regexp.MustCompile(`some`),
							},
						},
					},
				},
			},
			inputFilePath: "testdata/secret.txt",
			want: types.Secret{
				FilePath: "testdata/secret.txt",
				Findings: []types.SecretFinding{
					{
						RuleID:    basicRule.ID,
						Type:      basicRule.Type,
						Severity:  basicRule.Severity,
						Title:     basicRule.Title,
						StartLine: 4,
						EndLine:   5,
						Match:     "*****",
					},
				},
			},
		},
		{
			name: "rule exclude block",
			fields: fields{
				Rules: []secret.Rule{
					{
						ID:       basicRule.ID,
						Type:     basicRule.Type,
						Severity: basicRule.Severity,
						Title:    basicRule.Title,
						Regex:    basicRule.Regex,
						ExcludeBlocks: secret.ExcludeBlocks{
							Title: "Exclude blocks",
							Regexes: []*regexp.Regexp{
								regexp.MustCompile(`--- ignore block start ---(.|\s)*--- ignore block stop ---`),
							},
						},
					},
				},
			},
			inputFilePath: "testdata/secret.txt",
			want: types.Secret{
				FilePath: "testdata/secret.txt",
				Findings: []types.SecretFinding{
					{
						RuleID:    basicRule.ID,
						Type:      basicRule.Type,
						Severity:  basicRule.Severity,
						Title:     basicRule.Title,
						StartLine: 4,
						EndLine:   5,
						Match:     "*****",
					},
				},
			},
		},
		{
			name: "global allowlist path",
			fields: fields{
				Rules: []secret.Rule{
					basicRule,
				},
				AllowList: secret.AllowList{
					Title: "Allowlist",
					Paths: []*regexp.Regexp{
						regexp.MustCompile(`test`),
					},
				},
			},
			inputFilePath: "testdata/secret.txt",
			want:          types.Secret{},
		},
		{
			name: "global allowlist regex",
			fields: fields{
				Rules: []secret.Rule{
					basicRule,
				},
				AllowList: secret.AllowList{
					Title: "Allowlist",
					Regexes: []*regexp.Regexp{
						regexp.MustCompile(`some`),
					},
				},
			},
			inputFilePath: "testdata/secret.txt",
			want: types.Secret{
				FilePath: "testdata/secret.txt",
				Findings: []types.SecretFinding{
					{
						RuleID:    basicRule.ID,
						Type:      basicRule.Type,
						Severity:  basicRule.Severity,
						Title:     basicRule.Title,
						StartLine: 4,
						EndLine:   5,
						Match:     "*****",
					},
				},
			},
		},
		{
			name: "global exclude block",
			fields: fields{
				Rules: []secret.Rule{
					{
						ID:       basicRule.ID,
						Type:     basicRule.Type,
						Severity: basicRule.Severity,
						Title:    basicRule.Title,
						Regex:    basicRule.Regex,
					},
				},
				ExcludeBlocks: secret.ExcludeBlocks{
					Title: "Exclude blocks",
					Regexes: []*regexp.Regexp{
						regexp.MustCompile(`--- ignore block start ---(.|\s)*--- ignore block stop ---`),
					},
				},
			},
			inputFilePath: "testdata/secret.txt",
			want: types.Secret{
				FilePath: "testdata/secret.txt",
				Findings: []types.SecretFinding{
					{
						RuleID:    basicRule.ID,
						Type:      basicRule.Type,
						Severity:  basicRule.Severity,
						Title:     basicRule.Title,
						StartLine: 4,
						EndLine:   5,
						Match:     "*****",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := secret.NewScanner("", tt.fields.Rules, tt.fields.AllowList, tt.fields.ExcludeBlocks)
			content, err := ioutil.ReadFile(tt.inputFilePath)
			require.NoError(t, err)
			got := s.Scan(secret.ScanArgs{tt.inputFilePath, content})
			assert.Equal(t, tt.want, got)
		})
	}
}
