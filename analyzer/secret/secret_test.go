package secret_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/secret"
	"github.com/aquasecurity/fanal/types"
)

func TestSecretAnalyzer(t *testing.T) {
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
		name       string
		configPath string
		filePath   string
		want       *analyzer.AnalysisResult
	}{
		{
			name:       "return results",
			configPath: "testdata/config.yaml",
			filePath:   "testdata/secret.txt",
			want: &analyzer.AnalysisResult{
				Secrets: []types.Secret{{
					FilePath: "testdata/secret.txt",
					Findings: []types.SecretFinding{wantFinding1, wantFinding2},
				},
				},
			},
		},
		{
			name:       "return nil when no results",
			configPath: "",
			filePath:   "testdata/secret.txt",
			want:       nil,
		},
		{
			name:       "skip binary file",
			configPath: "",
			filePath:   "testdata/binaryfile",
			want:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := secret.NewSecretAnalyzer(tt.configPath)
			require.NoError(t, err)
			content, err := os.Open(tt.filePath)
			require.NoError(t, err)

			got, err := a.Analyze(context.TODO(), analyzer.AnalysisInput{
				FilePath: tt.filePath,
				Content:  content,
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
