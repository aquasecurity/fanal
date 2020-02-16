package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/fanal/types"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

const (
	cacheDirName = "fanal"

	// layerBucket stores os, package and library information per layer ID
	layerBucket = "layer"
	// decompressedDigestBucket stores a mapping from any digest to an uncompressed digest.
	decompressedDigestBucket = "decompressed"
)

var (
	replacer = strings.NewReplacer("/", "_")
)

type Cache interface {
	LayerCache
	LocalLayerCache
}

// LayerCache uses local or remote cache
type LayerCache interface {
	MissingLayers(layerIDs []string) (missingLayerIDs []string, err error)
	PutLayer(layerID, decompressedLayerID string, layerInfo types.LayerInfo) (err error)
}

// LocalLayerCache always uses local cache
type LocalLayerCache interface {
	GetLayer(layerID string) (layerBlob []byte)
	Clear() (err error)
}

type FSCache struct {
	db        *bolt.DB
	directory string
}

func NewFSCache(cacheDir string) (FSCache, error) {
	dir := filepath.Join(cacheDir, cacheDirName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return FSCache{}, err
	}

	db, err := bolt.Open(filepath.Join(dir, "fanal.db"), 0600, nil)
	if err != nil {
		return FSCache{}, err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range []string{layerBucket, decompressedDigestBucket} {
			if _, err := tx.CreateBucketIfNotExists([]byte(bucket)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return FSCache{}, err
	}

	return FSCache{
		db:        db,
		directory: dir,
	}, nil
}

func (fs FSCache) GetLayer(layerID string) []byte {
	var b []byte
	_ = fs.db.View(func(tx *bolt.Tx) error {
		// get a decompressed layer ID
		decompressedBucket := tx.Bucket([]byte(decompressedDigestBucket))
		d := decompressedBucket.Get([]byte(layerID))
		if d != nil {
			layerID = string(d)
		}

		bucket := tx.Bucket([]byte(layerBucket))
		b = bucket.Get([]byte(layerID))
		return nil
	})
	return b
}

func (fs FSCache) PutLayer(layerID, decompressedLayerID string, layerInfo types.LayerInfo) error {
	b, err := json.Marshal(layerInfo)
	if err != nil {
		return err
	}
	err = fs.db.Update(func(tx *bolt.Tx) error {
		// store a mapping from a layer ID to a decompressed layer ID.
		if layerID != decompressedLayerID {
			decompressedBucket := tx.Bucket([]byte(decompressedDigestBucket))
			err := decompressedBucket.Put([]byte(layerID), []byte(decompressedLayerID))
			if err != nil {
				return err
			}
		}

		layerBucket := tx.Bucket([]byte(layerBucket))
		err = layerBucket.Put([]byte(decompressedLayerID), b)
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
		decompressedBucket := tx.Bucket([]byte(decompressedDigestBucket))
		bucket := tx.Bucket([]byte(layerBucket))
		for _, layerID := range layerIDs {
			// get a decompressed layer ID
			d := decompressedBucket.Get([]byte(layerID))
			if d != nil {
				layerID = string(d)
			}

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

func (fs FSCache) Clear() error {
	_ = fs.db.Close()
	if err := os.RemoveAll(fs.directory); err != nil {
		return xerrors.New("failed to remove cache")
	}
	return nil
}
