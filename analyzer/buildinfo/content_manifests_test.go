package buildinfo

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
)

func Test_contentManifestAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		want    *analyzer.AnalysisResult
		wantErr bool
	}{
		{
			name: "happy path",
			content: []byte(`
{
    "metadata": {
        "icm_version": 1,
        "icm_spec": "https://raw.githubusercontent.com/containerbuildsystem/atomic-reactor/master/atomic_reactor/schemas/content_manifest.json",
        "image_layer_index": 4
    },
    "content_sets": [
        "rhel-8-for-x86_64-baseos-rpms",
        "rhel-8-for-x86_64-appstream-rpms"
    ],
    "image_contents": []
}`),
			want: &analyzer.AnalysisResult{
				BuildInfo: &analyzer.BuildInfo{
					ContentSets: []string{
						"rhel-8-for-x86_64-baseos-rpms",
						"rhel-8-for-x86_64-appstream-rpms",
					},
				},
			},
		},
		{
			name:    "broken json",
			content: []byte(`{"content_sets": 1}`),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := contentManifestAnalyzer{}
			got, err := a.Analyze(analyzer.AnalysisTarget{
				FilePath: "root/buildinfo/content_manifests/ubi8-container-8.3-227.json",
				Content:  tt.content,
			})
			if tt.wantErr {
				require.NotNil(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_contentManifestAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path",
			filePath: "root/buildinfo/content_manifests/nodejs-12-container-1-66.json",
			want:     true,
		},
		{
			name:     "sad path",
			filePath: "root/buildinfo/content_manifests/nodejs-12-container-1-66.xml",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := contentManifestAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
