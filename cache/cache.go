package cache

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/aquasecurity/fanal/types"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

const (
	cacheDirName = "fanal"

	// imageBucket stores image information with image ID
	imageBucket = "image"
	// layerBucket stores os, package and library information per layer ID
	layerBucket = "layer"
	// decompressedDigestBucket stores a mapping from any digest to an uncompressed digest.
	decompressedDigestBucket = "decompressed"
)

type Cache interface {
	ImageCache
	LocalImageCache
}

// ImageCache uses local or remote cache
type ImageCache interface {
	MissingLayers(imageID string, layerIDs []string) (missingImage bool, missingLayerIDs []string, err error)
	PutImage(imageID string, imageConfig types.ImageInfo) (err error)
	PutLayer(layerID, decompressedLayerID string, layerInfo types.LayerInfo) (err error)
}

// LocalImageCache always uses local cache
type LocalImageCache interface {
	GetImage(imageID string) (imageConfig types.ImageInfo, err error)
	GetLayer(layerID string) (layerInfo types.LayerInfo)
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
		for _, bucket := range []string{imageBucket, layerBucket, decompressedDigestBucket} {
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
				return xerrors.Errorf("unable to store a pair of compressed/decompressed layer IDs: %w", err)
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
func (fs FSCache) GetImage(imageID string) (types.ImageInfo, error) {
	var blob []byte
	err := fs.db.View(func(tx *bolt.Tx) error {
		imageBucket := tx.Bucket([]byte(imageBucket))
		blob = imageBucket.Get([]byte(imageID))
		return nil
	})
	if err != nil {
		return types.ImageInfo{}, err
	}

	var info types.ImageInfo
	if err := json.Unmarshal(blob, &info); err != nil {
		return types.ImageInfo{}, err
	}
	return info, nil
}

func (fs FSCache) PutImage(imageID string, imageConfig types.ImageInfo) (err error) {
	b, err := json.Marshal(imageConfig)
	if err != nil {
		return err
	}

	err = fs.db.Update(func(tx *bolt.Tx) error {
		imageBucket := tx.Bucket([]byte(imageBucket))
		err = imageBucket.Put([]byte(imageID), b)
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
func (fs FSCache) MissingLayers(imageID string, layerIDs []string) (bool, []string, error) {
	var missingImage bool
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
				continue
			}

			// check schema version in JSON
			var l types.LayerInfo
			if err := json.Unmarshal(b, &l); err != nil {
				missingLayerIDs = append(missingLayerIDs, layerID)
				continue
			}
			if l.SchemaVersion != types.LayerJSONSchemaVersion {
				missingLayerIDs = append(missingLayerIDs, layerID)
			}

		}
		return nil
	})
	if err != nil {
		return nil, err
		return false, nil, err
	}
	return missingLayerIDs, nil

	// get image info
	imageInfo, err := fs.GetImage(imageID)
	if err != nil {
		// error means cache missed image info
		return true, missingLayerIDs, nil
	}
	if imageInfo.SchemaVersion != types.ImageJSONSchemaVersion {
		missingImage = true
	}
	return missingImage, missingLayerIDs, nil
}

func (fs FSCache) Clear() error {
	if err := fs.db.Close(); err != nil {
		return err
	}
	if err := os.RemoveAll(fs.directory); err != nil {
		return xerrors.New("failed to remove cache")
	}
	return nil
}
