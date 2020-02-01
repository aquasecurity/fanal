package cache

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/fanal/types"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

const (
	cacheDirName = "fanal"
	layerBucket  = "layers"
)

var (
	replacer = strings.NewReplacer("/", "_")
)

type Cache interface {
	Get(key string) (reader io.ReadCloser)
	GetLayer(layerID string) []byte
	PutLayer(layerID string, layerInfo types.LayerInfo) error
	MissingLayers(layers []string) (missingLayerIDs []string, err error)
	Set(key string, value interface{}) (err error)
	SetBytes(key string, value []byte) (err error)
	Clear() (err error)
}

type FSCache struct {
	db        *bolt.DB
	directory string
}

func New(cacheDir string) (Cache, error) {
	dir := filepath.Join(cacheDir, cacheDirName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	db, err := bolt.Open(filepath.Join(dir, "fanal.db"), 0600, nil)
	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range []string{layerBucket} {
			if _, err := tx.CreateBucketIfNotExists([]byte(bucket)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &FSCache{
		db:        db,
		directory: dir,
	}, nil
}

func (fs FSCache) Get(key string) io.ReadCloser {
	filePath := filepath.Join(fs.directory, replacer.Replace(key))
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}

	return f
}

func (fs FSCache) GetLayer(layerID string) []byte {
	var b []byte
	_ = fs.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(layerBucket))
		b = bucket.Get([]byte(layerID))
		return nil
	})
	return b
}

func (fs FSCache) PutLayer(layerID string, layerInfo types.LayerInfo) error {
	b, err := json.Marshal(layerInfo)
	if err != nil {
		return err
	}
	err = fs.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(layerBucket))
		err := bucket.Put([]byte(layerID), b)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (fs FSCache) MissingLayers(layerIDs []string) ([]string, error) {
	var missingLayerIDs []string
	err := fs.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(layerBucket))
		for _, layerID := range layerIDs {
			b := bucket.Get([]byte(layerID))
			if b == nil {
				missingLayerIDs = append(missingLayerIDs, layerID)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return missingLayerIDs, nil
}

func (fs FSCache) Set(key string, value interface{}) error {
	//filePath := filepath.Join(fs.directory, replacer.Replace(key))
	//if err := os.MkdirAll(fs.directory, os.ModePerm); err != nil {
	//	return nil, xerrors.Errorf("failed to mkdir all: %w", err)
	//}
	//cacheFile, err := os.Create(filePath)
	//if err != nil {
	//	return r, xerrors.Errorf("failed to create cache file: %w", err)
	//}
	//
	//tee := io.TeeReader(r, cacheFile)
	return nil
}

func (fs FSCache) SetBytes(key string, b []byte) error {
	filePath := filepath.Join(fs.directory, replacer.Replace(key))
	if err := os.MkdirAll(fs.directory, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to mkdir all: %w", err)
	}
	cacheFile, err := os.Create(filePath)
	if err != nil {
		return xerrors.Errorf("failed to create cache file: %w", err)
	}

	if _, err := cacheFile.Write(b); err != nil {
		return xerrors.Errorf("cache write error: %w", err)
	}
	return nil
}

func (fs FSCache) Clear() error {
	_ = fs.db.Close()
	if err := os.RemoveAll(fs.directory); err != nil {
		return xerrors.New("failed to remove cache")
	}
	return nil
}
