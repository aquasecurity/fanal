package licensing

import (
	"errors"
	"os"

	"github.com/aquasecurity/fanal/licensing/classification"
	"github.com/aquasecurity/fanal/licensing/config"
	"github.com/aquasecurity/fanal/log"
	"github.com/aquasecurity/fanal/types"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"
)

type Scanner struct {
	classifier *classification.Classifier
}

var defaultConfig = config.Config{
	// set the confidence threshold to an arbitrary 70% confidence
	MatchConfidenceThreshold: 0.7,

	// check the headers of human readable source code files for headers by default
	IncludeHeaders: true,

	// default ignored list - taken from popular license from the open source initiative https://opensource.org/licenses
	IgnoredLicences: []string{
		"Apache-2.0",
		"BSD-3-Clause",
		"BSD-2-Clause",
		"GPL-2.0",
		"GPL-3.0",
		"LGPL-2.1",
		"LGPL-3.0",
		"MIT",
		"MPL-2.0",
		"CDDL-1.0",
		"EPL-2.0",
	},
}

type ScanArgs struct {
	FilePath string
	Content  []byte
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

func (s Scanner) Scan(scanArgs ScanArgs) types.License {

	license, err := s.classifier.Classify(scanArgs.FilePath, scanArgs.Content)
	if err != nil {
		log.Logger.Debugf("Name scan failed while scanning %s: %w", scanArgs.FilePath, err)
	}

	return license
}
