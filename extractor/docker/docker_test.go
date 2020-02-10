package docker

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"testing"

	"gotest.tools/assert"

	"github.com/opencontainers/go-digest"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/extractor/image"
	"github.com/aquasecurity/fanal/types"
)

func TestExtractor_ExtractLayerFiles(t *testing.T) {
	type fields struct {
		option types.DockerOption
		image  image.RealImage
	}
	type args struct {
		ctx       context.Context
		dig       digest.Digest
		filenames []string
	}
	tests := []struct {
		name                string
		fields              fields
		args                args
		expectedDigest      digest.Digest
		expectedFileMap     extractor.FileMap
		expectedOpqDirs     []string
		expectedWhFiles     []string
		getLayerExpectation image.GetLayerExpectation
		wantErr             string
	}{
		{
			name: "happy path",
			getLayerExpectation: image.GetLayerExpectation{
				Args: image.GetLayerArgs{
					CtxAnything: true,
					Dig:         "sha256:da550bbd659298750df72fc8c1eafe8df272935e1b287bf072f5a630a98a57b4",
				},
				Returns: image.GetLayerReturns{
					Reader: func() io.ReadCloser {
						f, err := os.Open("testdata/normal.tar")
						require.NoError(t, err)
						return f
					}(),
				},
			},
			args: args{
				ctx:       nil,
				dig:       "sha256:da550bbd659298750df72fc8c1eafe8df272935e1b287bf072f5a630a98a57b4",
				filenames: []string{"var/foo"},
			},
			expectedDigest: "sha256:f75441026d68038ca80e92f342fb8f3c0f1faeec67b5a80c98f033a65beaef5a",
			expectedFileMap: extractor.FileMap{
				"var/foo": []byte(""),
			},
		},
		{
			name: "opq file path",
			getLayerExpectation: image.GetLayerExpectation{
				Args: image.GetLayerArgs{
					CtxAnything: true,
					Dig:         "sha256:852347c2db814b0930034e93053f8bfe9736430431f3b2dbbdf42769592fa626",
				},
				Returns: image.GetLayerReturns{
					Reader: func() io.ReadCloser {
						f, err := os.Open("testdata/opq.tar")
						require.NoError(t, err)
						return f
					}(),
				},
			},
			args: args{
				ctx:       nil,
				dig:       "sha256:852347c2db814b0930034e93053f8bfe9736430431f3b2dbbdf42769592fa626",
				filenames: []string{"etc/test/"},
			},
			expectedDigest: "sha256:852347c2db814b0930034e93053f8bfe9736430431f3b2dbbdf42769592fa626",
			expectedFileMap: extractor.FileMap{
				"etc/test/test2": []byte(""),
			},
			expectedOpqDirs: []string{
				"etc/test/",
			},
			expectedWhFiles: []string{
				"var/foo",
			},
		},
		{
			name: "sad path with GetLayer fails",
			getLayerExpectation: image.GetLayerExpectation{
				Args: image.GetLayerArgs{
					CtxAnything: true,
					Dig:         "sha256:da550bbd659298750df72fc8c1eafe8df272935e1b287bf072f5a630a98a57b4",
				},
				Returns: image.GetLayerReturns{
					Err: errors.New("GetLayer failed"),
				},
			},
			args: args{
				ctx:       nil,
				dig:       "sha256:da550bbd659298750df72fc8c1eafe8df272935e1b287bf072f5a630a98a57b4",
				filenames: []string{"var/foo"},
			},
			expectedDigest: "sha256:f75441026d68038ca80e92f342fb8f3c0f1faeec67b5a80c98f033a65beaef5a",
			expectedFileMap: extractor.FileMap{
				"var/foo": []byte(""),
			},
			wantErr: "GetLayer failed",
		},
		{
			name: "sad path with extractFiles fails due to invalid file",
			getLayerExpectation: image.GetLayerExpectation{
				Args: image.GetLayerArgs{
					CtxAnything: true,
					Dig:         "sha256:da550bbd659298750df72fc8c1eafe8df272935e1b287bf072f5a630a98a57b4",
				},
				Returns: image.GetLayerReturns{
					Reader: func() io.ReadCloser {
						f, err := os.Open("testdata/invalidgzvalidtar.tar.gz")
						require.NoError(t, err)
						return f
					}(),
				},
			},
			args: args{
				ctx:       nil,
				dig:       "sha256:da550bbd659298750df72fc8c1eafe8df272935e1b287bf072f5a630a98a57b4",
				filenames: []string{"var/foo"},
			},
			wantErr: "unexpected EOF",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockImg := new(image.MockImage)
			mockImg.ApplyGetLayerExpectation(tt.getLayerExpectation)

			d := Extractor{
				option: tt.fields.option,
				image:  mockImg,
			}
			actualDigest, actualFileMap, actualOpqDirs, actualWhFiles, err := d.ExtractLayerFiles(tt.args.ctx, tt.args.dig, tt.args.filenames)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.ErrorContains(t, err, tt.wantErr, tt.name)
				return
			} else {
				require.NoError(t, err, tt.name)
			}

			if actualDigest != tt.expectedDigest {
				t.Errorf("ExtractLayerFiles() actualDigest = %v, expectedDigest %v", actualDigest, tt.expectedDigest)
			}
			if !reflect.DeepEqual(actualFileMap, tt.expectedFileMap) {
				t.Errorf("ExtractLayerFiles() actualFileMap = %v, expectedFileMap %v", actualFileMap, tt.expectedFileMap)
			}
			if !reflect.DeepEqual(actualOpqDirs, tt.expectedOpqDirs) {
				t.Errorf("ExtractLayerFiles() actualOpqDirs = %v, expectedOpqDirs %v", actualOpqDirs, tt.expectedOpqDirs)
			}
			if !reflect.DeepEqual(actualWhFiles, tt.expectedWhFiles) {
				t.Errorf("ExtractLayerFiles() actualWhFiles = %v, expectedWhFiles %v", actualWhFiles, tt.expectedWhFiles)
			}
		})
	}
}
