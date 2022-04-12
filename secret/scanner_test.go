package secret_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/secret"
	"github.com/aquasecurity/fanal/types"
)

func TestSecretScanner(t *testing.T) {
	wantFinding1 := types.SecretFinding{
		RuleID:    "rule1",
		Category:  "general",
		Title:     "Generic Rule",
		Severity:  "HIGH",
		StartLine: 2,
		EndLine:   3,
		Match:     "generic secret line secret=\"*****\"",
	}
	wantFinding2 := types.SecretFinding{
		RuleID:    "rule1",
		Category:  "general",
		Title:     "Generic Rule",
		Severity:  "HIGH",
		StartLine: 4,
		EndLine:   5,
		Match:     "secret=\"*****\"",
	}
	tests := []struct {
		name          string
		configPath    string
		inputFilePath string
		want          types.Secret
	}{
		{
			name:          "find match",
			configPath:    "testdata/config.yaml",
			inputFilePath: "testdata/secret.txt",
			want: types.Secret{
				FilePath: "testdata/secret.txt",
				Findings: []types.SecretFinding{wantFinding1, wantFinding2},
			},
		},
		{
			name:          "allow-rule path",
			configPath:    "testdata/allow-path.yaml",
			inputFilePath: "testdata/secret.txt",
			want:          types.Secret{},
		},
		{
			name:          "allow-rule regex",
			configPath:    "testdata/allow-regex.yaml",
			inputFilePath: "testdata/secret.txt",
			want: types.Secret{
				FilePath: "testdata/secret.txt",
				Findings: []types.SecretFinding{wantFinding1},
			},
		},
		{
			name:          "exclude-block regexes",
			configPath:    "testdata/exclude-block.yaml",
			inputFilePath: "testdata/secret.txt",
			want: types.Secret{
				FilePath: "testdata/secret.txt",
				Findings: []types.SecretFinding{wantFinding2},
			},
		},
		{
			name:          "global allow-rule path",
			configPath:    "testdata/global-allow-path.yaml",
			inputFilePath: "testdata/secret.txt",
			want: types.Secret{
				FilePath: "testdata/secret.txt",
				Findings: []types.SecretFinding{wantFinding1, wantFinding2},
			},
		},
		{
			name:          "global allow-rule regex",
			configPath:    "testdata/global-allow-regex.yaml",
			inputFilePath: "testdata/secret.txt",
			want: types.Secret{
				FilePath: "testdata/secret.txt",
				Findings: []types.SecretFinding{wantFinding1},
			},
		},
		{
			name:          "global exclude-block regexes",
			configPath:    "testdata/global-exclude-block.yaml",
			inputFilePath: "testdata/secret.txt",
			want: types.Secret{
				FilePath: "testdata/secret.txt",
				Findings: []types.SecretFinding{wantFinding2},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := secret.NewScanner(tt.configPath)
			require.NoError(t, err)

			content, err := os.ReadFile(tt.inputFilePath)
			require.NoError(t, err)

			got := s.Scan(secret.ScanArgs{
				FilePath: tt.inputFilePath,
				Content:  content},
			)
			assert.Equal(t, tt.want, got)
		})
	}
}
