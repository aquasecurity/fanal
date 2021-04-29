package library_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/types"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestAnalyze(t *testing.T) {
	type args struct {
		analyzerType string
		filePath     string
		content      []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *analyzer.AnalysisResult
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				analyzerType: library.GoBinary,
				filePath:     "app/myweb",
				content:      []byte("happy"),
			},
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     library.GoBinary,
						FilePath: "app/myweb",
						Libraries: []types.LibraryInfo{
							{
								Library: godeptypes.Library{
									Name:    "test",
									Version: "1.2.3",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "empty",
			args: args{
				analyzerType: library.GoBinary,
				filePath:     "app/myweb",
				content:      []byte(""),
			},
			want: nil,
		},
		{
			name: "sad path",
			args: args{
				analyzerType: library.Jar,
				filePath:     "app/myweb",
				content:      []byte("sad"),
			},
			wantErr: "unexpected error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parse := func(r io.Reader) ([]godeptypes.Library, error) {
				b, err := io.ReadAll(r)
				require.NoError(t, err)

				switch string(b) {
				case "happy":
					return []godeptypes.Library{{Name: "test", Version: "1.2.3"}}, nil
				case "sad":
					return nil, xerrors.New("unexpected error")
				}

				return nil, nil
			}

			got, err := library.Analyze(tt.args.analyzerType, tt.args.filePath, tt.args.content, parse)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
