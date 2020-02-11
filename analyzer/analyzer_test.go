package analyzer_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/aquasecurity/fanal/analyzer"

	_ "github.com/aquasecurity/fanal/analyzer/command/apk"
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"

	//_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"

	"github.com/aquasecurity/fanal/extractor/docker"
	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/types"
)

//type mockDockerExtractor struct {
//	extract func(ctx context.Context, imageRef image.Reference, transports, filenames []string) (extractor.FileMap, error)
//}
//
//func (mde mockDockerExtractor) Extract(ctx context.Context, imageRef image.Reference, transports, filenames []string) (extractor.FileMap, error) {
//	if mde.extract != nil {
//		return mde.extract(ctx, imageRef, transports, filenames)
//	}
//	return extractor.FileMap{}, nil
//}
//
//func (mde mockDockerExtractor) ExtractFiles(layer io.Reader, filenames []string) (extractor.FileMap, extractor.OPQDirs, error) {
//	panic("implement me")
//}
//
//type mockOSAnalyzer struct{}
//
//func (m mockOSAnalyzer) Analyze(extractor.FileMap) (types.OS, error) {
//	panic("implement me")
//}
//
//func (m mockOSAnalyzer) RequiredFiles() []string {
//	return []string{"file1", "file2"}
//}
//
//func TestConfig_Analyze(t *testing.T) {
//	testCases := []struct {
//		name            string
//		extractFunc     func(ctx context.Context, imageRef image.Reference, transports, filenames []string) (extractor.FileMap, error)
//		expectedError   error
//		expectedFileMap extractor.FileMap
//	}{
//		{
//			name: "happy path with no docker installed or no image found",
//			extractFunc: func(ctx context.Context, imageRef image.Reference, transports, filenames []string) (maps extractor.FileMap, e error) {
//				return extractor.FileMap{
//					"file1": []byte{0x1, 0x2, 0x3},
//					"file2": []byte{0x4, 0x5, 0x6},
//				}, nil
//			},
//			expectedFileMap: extractor.FileMap{
//				"file1": []byte{0x1, 0x2, 0x3},
//				"file2": []byte{0x4, 0x5, 0x6},
//			},
//		},
//	}
//
//	for _, tc := range testCases {
//		RegisterOSAnalyzer(mockOSAnalyzer{})
//
//		ac := Config{Extractor: mockDockerExtractor{
//			extract: tc.extractFunc,
//		}}
//		fm, err := ac.Analyze(context.TODO(), "fooimage")
//		assert.Equal(t, tc.expectedError, err, tc.name)
//		assert.Equal(t, tc.expectedFileMap, fm, tc.name)
//
//		// reset the gnarly global state
//		osAnalyzers = []OSAnalyzer{}
//	}
//}

//func TestConfig_AnalyzeFile(t *testing.T) {
//	testCases := []struct {
//		name            string
//		extractFunc     func(ctx context.Context, imageReference image.Reference, transports, filenames []string) (extractor.FileMap, error)
//		inputFile       string
//		expectedError   error
//		expectedFileMap extractor.FileMap
//	}{
//		{
//			name:            "happy path, valid tar.gz file",
//			inputFile:       "testdata/alpine.tar.gz",
//			expectedFileMap: extractor.FileMap{},
//		},
//		{
//			name:            "happy path, valid tar file",
//			expectedFileMap: extractor.FileMap{},
//			inputFile:       "../utils/testdata/test.tar",
//		},
//		{
//			name:          "sad path, valid file but ExtractFromFile fails",
//			expectedError: errors.New("failed to extract files: extract from file failed"),
//			extractFunc: func(ctx context.Context, imageRef image.Reference, transports, filenames []string) (fileMap extractor.FileMap, err error) {
//				return nil, errors.New("extract from file failed")
//			},
//		},
//	}
//
//	for _, tc := range testCases {
//		ac := Config{
//			Extractor: mockDockerExtractor{
//				extract: tc.extractFunc,
//			},
//		}
//
//		fm, err := ac.AnalyzeFile(context.Background(), tc.inputFile)
//		switch {
//		case tc.expectedError != nil:
//			assert.Equal(t, tc.expectedError.Error(), err.Error(), tc.name)
//		default:
//			assert.NoError(t, err, tc.name)
//		}
//		assert.Equal(t, tc.expectedFileMap, fm, tc.name)
//	}
//
//}

func TestConfig_Analyze(t *testing.T) {
	type fields struct {
		Extractor extractor.Extractor
		Cache     cache.LayerCache
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name                    string
		imagePath               string
		fields                  fields
		args                    args
		missingLayerExpectation cache.MissingLayersExpectation
		putLayerExpectation     cache.PutLayerExpectation
		want                    types.ImageInfo
		wantErr                 bool
	}{
		{
			name:      "happy path",
			imagePath: "testdata/alpine.tar.gz",
			missingLayerExpectation: cache.MissingLayersExpectation{
				Args: cache.MissingLayersArgs{
					LayerIDs: []string{"sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0"},
				},
				Returns: cache.MissingLayersReturns{
					MissingLayerIDs: []string{"sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0"},
				},
			},
			putLayerExpectation: cache.PutLayerExpectation{
				Args: cache.PutLayerArgs{
					LayerID:             "sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0",
					DecompressedLayerID: "sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0",
					LayerInfo: types.LayerInfo{
						SchemaVersion: 1,
						OS: &types.OS{
							Family: "alpine",
							Name:   "3.10.3",
						},
					},
				},
				Returns: cache.PutLayerReturns{},
			},
			want: types.ImageInfo{
				Name:     "testdata/alpine.tar.gz",
				ID:       "sha256:965ea09ff2ebd2b9eeec88cd822ce156f6674c7e99be082c7efac3c62f3ff652",
				LayerIDs: []string{"sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCache := new(cache.MockLayerCache)
			mockCache.ApplyMissingLayersExpectation(tt.missingLayerExpectation)
			mockCache.ApplyPutLayerExpectation(tt.putLayerExpectation)

			d, err := docker.NewDockerArchiveExtractor(context.Background(), tt.imagePath, types.DockerOption{})
			assert.NoError(t, err, tt.name)

			ac := analyzer.Config{
				Extractor: d,
				Cache:     mockCache,
			}
			got, err := ac.Analyze(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("Analyze() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Analyze() got = %v, want %v", got, tt.want)
			}
		})
	}
}
