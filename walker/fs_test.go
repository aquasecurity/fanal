package walker_test

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/walker"
)

func TestDir_Walk(t *testing.T) {
	type fields struct {
		skipFiles              []string
		skipDirs               []string
		disableDefaultSkipDirs bool
	}
	tests := []struct {
		name      string
		fields    fields
		rootDir   string
		analyzeFn walker.WalkFunc
		wantErr   string
	}{
		// {
		// 	name:    "happy path",
		// 	rootDir: "testdata/fs",
		// 	analyzeFn: func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		// 		if filePath == "testdata/fs/bar" {
		// 			got, err := opener()
		// 			require.NoError(t, err)

		// 			b, err := io.ReadAll(got)
		// 			require.NoError(t, err)

		// 			assert.Equal(t, "bar", string(b))
		// 		}
		// 		return nil
		// 	},
		// },
		// {
		// 	name:    "skip file",
		// 	rootDir: "testdata/fs",
		// 	fields: fields{
		// 		skipFiles: []string{"testdata/fs/bar"},
		// 	},
		// 	analyzeFn: func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		// 		if filePath == "testdata/fs/bar" {
		// 			assert.Fail(t, "skip files error", "%s should be skipped", filePath)
		// 		}
		// 		return nil
		// 	},
		// },
		// {
		// 	name:    "skip dir",
		// 	rootDir: "testdata/fs/",
		// 	fields: fields{
		// 		skipDirs: []string{"/testdata/fs/app/"},
		// 	},
		// 	analyzeFn: func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		// 		if strings.HasPrefix(filePath, "testdata/fs/app") {
		// 			assert.Fail(t, "skip dirs error", "%s should be skipped", filePath)
		// 		}
		// 		return nil
		// 	},
		// },
		// {
		// 	name:    "sad path",
		// 	rootDir: "testdata/fs",
		// 	analyzeFn: func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		// 		return errors.New("error")
		// 	},
		// 	wantErr: "failed to analyze file",
		// },
		{
			name:    "default skip  dir",
			rootDir: "testdata/vendor",
			fields:  fields{},
			analyzeFn: func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
				return errors.New("unexpected function call")
			},
		},
		{
			name:    "disable default skip dir",
			rootDir: "testdata/vendor",
			fields: fields{
				disableDefaultSkipDirs: true,
			},
			analyzeFn: func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
				assert.True(t, strings.HasSuffix(filePath, "foo"))
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := walker.NewFS(tt.fields.skipFiles, tt.fields.skipDirs, tt.fields.disableDefaultSkipDirs)

			err := w.Walk(tt.rootDir, tt.analyzeFn)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}
