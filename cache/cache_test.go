package cache

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/fanal/types"
	depTypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func newTempDB(dbPath string) (string, error) {
	dir, err := ioutil.TempDir("", "cache-test")
	if err != nil {
		return "", err
	}

	if dbPath != "" {
		d := filepath.Join(dir, "fanal")
		if err = os.MkdirAll(d, 0700); err != nil {
			return "", err
		}

		dst := filepath.Join(d, "fanal.db")
		if _, err = copyFile(dbPath, dst); err != nil {
			return "", err
		}
	}

	return dir, nil
}

func copyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	n, err := io.Copy(destination, source)
	return n, err
}

func TestFSCache_GetLayer(t *testing.T) {
	type args struct {
		layerID string
	}
	tests := []struct {
		name   string
		dbPath string
		args   args
		want   types.LayerInfo
	}{
		{
			name:   "happy path",
			dbPath: "testdata/fanal.db",
			args: args{
				layerID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
			},
			want: types.LayerInfo{
				SchemaVersion: 2,
				OS: &types.OS{
					Family: "alpine",
					Name:   "3.10",
				},
			},
		},
		{
			name:   "happy path: different decompressed layer ID",
			dbPath: "testdata/decompressed-layer-id.db",
			args: args{
				layerID: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
			},
			want: types.LayerInfo{
				SchemaVersion: 1,
				OS: &types.OS{
					Family: "alpine",
					Name:   "3.10",
				},
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "lib/apk/db/installed",
						Packages: []types.Package{
							{
								Name:    "musl",
								Version: "1.1.22-r3",
							},
						},
					},
				},
				Applications: []types.Application{
					{
						Type:     "composer",
						FilePath: "php-app/composer.lock",
						Libraries: []types.LibraryInfo{
							{
								Library: depTypes.Library{
									Name:    "guzzlehttp/guzzle",
									Version: "6.2.0",
								},
							},
							{
								Library: depTypes.Library{
									Name:    "guzzlehttp/promises",
									Version: "v1.3.1",
								},
							},
						},
					},
				},
				OpaqueDirs:    []string{"php-app/"},
				WhiteoutFiles: []string{"etc/foobar"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := newTempDB(tt.dbPath)
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			fs, err := NewFSCache(tmpDir)
			require.NoError(t, err)
			defer fs.Clear()

			got, err := fs.GetLayer(tt.args.layerID)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFSCache_PutLayer(t *testing.T) {
	type fields struct {
		db        *bolt.DB
		directory string
	}
	type args struct {
		layerID             string
		decompressedLayerID string
		layerInfo           types.LayerInfo
	}
	tests := []struct {
		name        string
		fields      fields
		args        args
		want        string
		wantLayerID string
		wantErr     string
	}{
		{
			name: "happy path",
			args: args{
				layerID:             "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
				decompressedLayerID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
				layerInfo: types.LayerInfo{
					SchemaVersion: 1,
					OS: &types.OS{
						Family: "alpine",
						Name:   "3.10",
					},
				},
			},
			want: `
				{
				  "SchemaVersion": 1,
				  "OS": {
				    "Family": "alpine",
				    "Name": "3.10"
				  }
				}`,
			wantLayerID: "",
		},
		{
			name: "happy path: different decompressed layer ID",
			args: args{
				layerID:             "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
				decompressedLayerID: "sha256:dab15cac9ebd43beceeeda3ce95c574d6714ed3d3969071caead678c065813ec",
				layerInfo: types.LayerInfo{
					SchemaVersion: 1,
					OS: &types.OS{
						Family: "alpine",
						Name:   "3.10",
					},
					PackageInfos: []types.PackageInfo{
						{
							FilePath: "lib/apk/db/installed",
							Packages: []types.Package{
								{
									Name:    "musl",
									Version: "1.1.22-r3",
								},
							},
						},
					},
					Applications: []types.Application{
						{
							Type:     "composer",
							FilePath: "php-app/composer.lock",
							Libraries: []types.LibraryInfo{
								{
									Library: depTypes.Library{
										Name:    "guzzlehttp/guzzle",
										Version: "6.2.0",
									},
								},
								{
									Library: depTypes.Library{
										Name:    "guzzlehttp/promises",
										Version: "v1.3.1",
									},
								},
							},
						},
					},
					OpaqueDirs:    []string{"php-app/"},
					WhiteoutFiles: []string{"etc/foobar"},
				},
			},
			want: `
				{
				  "SchemaVersion": 1,
				  "OS": {
				    "Family": "alpine",
				    "Name": "3.10"
				  },
				  "PackageInfos": [
				    {
				      "FilePath": "lib/apk/db/installed",
				      "Packages": [
				        {
				          "Name": "musl",
				          "Version": "1.1.22-r3"
				        }
				      ]
				    }
				  ],
				  "Applications": [
				    {
				      "Type": "composer",
				      "FilePath": "php-app/composer.lock",
				      "Libraries": [
                        {
                           "Library":{
                              "Name":"guzzlehttp/guzzle",
                              "Version":"6.2.0"
                           }
                        },
                        {
                           "Library":{
                              "Name":"guzzlehttp/promises",
                              "Version":"v1.3.1"
                           }
                        }
				      ]
				    }
				  ],
				  "OpaqueDirs": [
				    "php-app/"
				  ],
				  "WhiteoutFiles": [
				    "etc/foobar"
				  ]
				}`,
			wantLayerID: "sha256:dab15cac9ebd43beceeeda3ce95c574d6714ed3d3969071caead678c065813ec",
		},
		{
			name: "sad path no layerID",
			args: args{
				decompressedLayerID: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
			},
			wantErr: "key required",
		},
		{
			name: "sad path no decompressedLayerID",
			args: args{
				layerID: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
			},
			wantErr: "key required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := newTempDB("")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			fs, err := NewFSCache(tmpDir)
			require.NoError(t, err)
			defer fs.Clear()

			err = fs.PutLayer(tt.args.layerID, tt.args.decompressedLayerID, tt.args.layerInfo)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				require.NoError(t, err, tt.name)
			}

			fs.db.View(func(tx *bolt.Tx) error {
				// check decompressedDigestBucket
				decompressedBucket := tx.Bucket([]byte(decompressedDigestBucket))
				res := decompressedBucket.Get([]byte(tt.args.layerID))
				assert.Equal(t, tt.wantLayerID, string(res))

				layerBucket := tx.Bucket([]byte(layerBucket))
				b := layerBucket.Get([]byte(tt.args.decompressedLayerID))
				assert.JSONEq(t, tt.want, string(b))

				return nil
			})
		})
	}
}

func TestFSCache_PutImage(t *testing.T) {
	type args struct {
		imageID     string
		imageConfig types.ImageInfo
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				imageID: "sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4",
				imageConfig: types.ImageInfo{
					SchemaVersion: 1,
					Architecture:  "amd64",
					Created:       time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC),
					DockerVersion: "18.06.1-ce",
					OS:            "linux",
					HistoryPackages: []types.Package{
						{
							Name:    "musl",
							Version: "1.2.3",
						},
					},
				},
			},
			want: `
				{
				  "SchemaVersion": 1,
				  "Architecture": "amd64",
				  "Created": "2020-01-02T03:04:05Z",
				  "DockerVersion": "18.06.1-ce",
				  "OS": "linux",
				  "HistoryPackages": [
				    {
				      "Name": "musl",
				      "Version": "1.2.3"
				    }
				  ]
				}
				`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := newTempDB("")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			fs, err := NewFSCache(tmpDir)
			require.NoError(t, err)
			//defer fs.Clear()

			err = fs.PutImage(tt.args.imageID, tt.args.imageConfig)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				require.NoError(t, err, tt.name)
			}

			fs.db.View(func(tx *bolt.Tx) error {
				// check decompressedDigestBucket
				imageBucket := tx.Bucket([]byte(imageBucket))
				b := imageBucket.Get([]byte(tt.args.imageID))
				assert.JSONEq(t, tt.want, string(b))

				return nil
			})
		})
	}
}

func TestFSCache_MissingLayers(t *testing.T) {
	type args struct {
		imageID  string
		layerIDs []string
	}
	tests := []struct {
		name                string
		dbPath              string
		args                args
		wantMissingImage    bool
		wantMissingLayerIDs []string
		wantErr             string
	}{
		{
			name:   "happy path",
			dbPath: "testdata/fanal.db",
			args: args{
				imageID: "sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4",
				layerIDs: []string{
					"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
					"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
					"sha256:dab15cac9ebd43beceeeda3ce95c574d6714ed3d3969071caead678c065813ec",
				},
			},
			wantMissingImage: false,
			wantMissingLayerIDs: []string{
				"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
				"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
				"sha256:dab15cac9ebd43beceeeda3ce95c574d6714ed3d3969071caead678c065813ec",
			},
		},
		{
			name:   "happy path: different decompressed layer ID",
			dbPath: "testdata/decompressed-layer-id.db",
			args: args{
				imageID: "sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4",
				layerIDs: []string{
					"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
					"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
					"sha256:dab15cac9ebd43beceeeda3ce95c574d6714ed3d3969071caead678c065813ec",
				},
			},
			wantMissingImage: true,
			wantMissingLayerIDs: []string{
				"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
			},
		},
		{
			name:   "happy path: broken layer JSON",
			dbPath: "testdata/broken-layer.db",
			args: args{
				imageID: "sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4",
				layerIDs: []string{
					"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
				},
			},
			wantMissingImage: true,
			wantMissingLayerIDs: []string{
				"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
			},
		},
		{
			name:   "happy path: broken image JSON",
			dbPath: "testdata/broken-image.db",
			args: args{
				imageID: "sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4",
				layerIDs: []string{
					"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
				},
			},
			wantMissingImage: true,
			wantMissingLayerIDs: []string{
				"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
			},
		},
		{
			name:   "happy path: the schema version of image JSON doesn't match",
			dbPath: "testdata/different-image-schema.db",
			args: args{
				imageID: "sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4",
				layerIDs: []string{
					"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
				},
			},
			wantMissingImage: true,
			wantMissingLayerIDs: []string{
				"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := newTempDB(tt.dbPath)
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			fs, err := NewFSCache(tmpDir)
			require.NoError(t, err)
			defer fs.Clear()

			gotMissingImage, gotMissingLayerIDs, err := fs.MissingLayers(tt.args.imageID, tt.args.layerIDs)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				require.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.wantMissingImage, gotMissingImage, tt.name)
			assert.Equal(t, tt.wantMissingLayerIDs, gotMissingLayerIDs, tt.name)
		})
	}
}
