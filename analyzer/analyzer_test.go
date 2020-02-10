package analyzer

import (
	"context"
	"reflect"
	"testing"

	"github.com/aquasecurity/fanal/cache"

	"github.com/aquasecurity/fanal/types"

	"github.com/aquasecurity/fanal/extractor"
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
//
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

func TestConfig_Analyze1(t *testing.T) {
	type fields struct {
		Extractor extractor.Extractor
		Cache     cache.LayerCache
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name                    string
		fields                  fields
		args                    args
		missingLayerExpectation cache.MissingLayersExpectation
		want                    types.ImageInfo
		wantErr                 bool
	}{
		{
			name: "happy path",
			missingLayerExpectation: cache.MissingLayersExpectation{
				Args: cache.MissingLayersArgs{
					LayerIDs: []string{"sha256:abcd", "sha256:efgh"},
				},
				Returns: cache.MissingLayersReturns{
					MissingLayerIDs: []string{"sha256:efgh"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCache := new(cache.MockLayerCache)
			mockCache.ApplyMissingLayersExpectation(tt.missingLayerExpectation)

			ac := Config{
				Extractor: tt.fields.Extractor,
				Cache:     tt.fields.Cache,
			}
			got, err := ac.Analyze(tt.args.ctx)
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
