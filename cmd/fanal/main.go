package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aquasecurity/fanal/types"

	"github.com/aquasecurity/fanal/extractor/docker"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"

	"github.com/aquasecurity/fanal/analyzer"
	_ "github.com/aquasecurity/fanal/analyzer/command/apk"
	_ "github.com/aquasecurity/fanal/analyzer/library/bundler"
	_ "github.com/aquasecurity/fanal/analyzer/library/cargo"
	_ "github.com/aquasecurity/fanal/analyzer/library/composer"
	_ "github.com/aquasecurity/fanal/analyzer/library/npm"
	_ "github.com/aquasecurity/fanal/analyzer/library/pipenv"
	_ "github.com/aquasecurity/fanal/analyzer/library/poetry"
	_ "github.com/aquasecurity/fanal/analyzer/library/yarn"
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/os/amazonlinux"
	_ "github.com/aquasecurity/fanal/analyzer/os/debianbase"
	_ "github.com/aquasecurity/fanal/analyzer/os/opensuse"
	_ "github.com/aquasecurity/fanal/analyzer/os/redhatbase"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/dpkg"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/rpm"
	"github.com/aquasecurity/fanal/extractor"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() (err error) {
	ctx := context.Background()
	tarPath := flag.String("f", "-", "layer.tar path")
	clearCache := flag.Bool("clear", false, "clear cache")
	flag.Parse()

	if *clearCache {
		if err = cache.Clear(); err != nil {
			return xerrors.Errorf("error in cache clear: %w", err)
		}
	}

	args := flag.Args()

	opt := types.DockerOption{
		Timeout: 600 * time.Second,
	}

	ext, err := docker.NewDockerExtractor(opt)
	if err != nil {
		return err
	}
	ac := analyzer.AnalyzerConfig{Extractor: ext}

	var files extractor.FileMap
	if len(args) > 0 {
		files, err = ac.Analyze(ctx, args[0])
		if err != nil {
			return err
		}
	} else {
		rc, err := openStream(*tarPath)
		if err != nil {
			return err
		}

		files, err = ac.AnalyzeFile(ctx, rc)
		if err != nil {
			return err
		}
	}

	osFound, err := analyzer.GetOS(files)
	if err != nil {
		return err
	}
	fmt.Printf("%+v\n", osFound)

	pkgs, err := analyzer.GetPackages(files)
	if err != nil {
		return err
	}
	fmt.Printf("via image Packages: %d\n", len(pkgs))

	pkgs, err = analyzer.GetPackagesFromCommands(osFound, files)
	if err != nil {
		return err
	}
	fmt.Printf("via file Packages: %d\n", len(pkgs))

	libs, err := analyzer.GetLibraries(files)
	if err != nil {
		return err
	}
	for filepath, libList := range libs {
		fmt.Printf("%s: %d\n", filepath, len(libList))
	}
	return nil
}

func openStream(path string) (*os.File, error) {
	if path == "-" {
		if terminal.IsTerminal(0) {
			flag.Usage()
			os.Exit(64)
		} else {
			return os.Stdin, nil
		}
	}
	return os.Open(path)
}
