package license

import (
	"errors"
	"os"

	"github.com/aquasecurity/fanal/license/classification"
	"github.com/aquasecurity/fanal/license/config"
	"github.com/aquasecurity/fanal/log"
	"github.com/aquasecurity/fanal/types"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"
)

type Scanner struct {
	classifier *classification.Classifier
}

var defaultConfig = config.Config{
	MatchConfidenceThreshold: 0.7,
	IncludeHeaders:           true,
}

func NewScanner(configPath string) (Scanner, error) {

	if configPath == "" {
		return newDefaultScanner()
	}

	f, err := os.Open(configPath)
	if errors.Is(err, os.ErrNotExist) {
		log.Logger.Debugf("No secret config detected: %s", configPath)
		return newDefaultScanner()
	} else if err != nil {

		return Scanner{}, xerrors.Errorf("file open error %s: %w", configPath, err)
	}
	defer func() { _ = f.Close() }()

	log.Logger.Infof("Loading %s for secret scanning...", configPath)

	var cfg config.Config
	if err = yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return Scanner{}, xerrors.Errorf("license config decode error: %w", err)
	}

	classifier, err := classification.NewClassifier(cfg)
	if err != nil {
		return Scanner{}, xerrors.Errorf("classifier could not be created: %w", err)
	}
	return Scanner{classifier: classifier}, nil
}

func newDefaultScanner() (Scanner, error) {
	classifier, err := classification.NewClassifier(defaultConfig)
	if err != nil {
		return Scanner{}, xerrors.Errorf("classifier could not be created: %w", err)
	}
	return Scanner{classifier: classifier}, nil
}

func (s Scanner) Scan(filePath string) types.License {

	license, err := s.classifier.Classify(filePath)
	if err != nil {
		log.Logger.Debugf("Name scan failed while scanning %s: %w", filePath, err)
	}

	return license
}
