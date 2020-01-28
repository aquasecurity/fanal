package rpmcmd

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

func init() {
	analyzer.RegisterPkgAnalyzer(&rpmCmdPkgAnalyzer{})
}

var (
	RPMCommandError = xerrors.New("rpm command error")
)

type rpmCmdPkgAnalyzer struct{}

func (a rpmCmdPkgAnalyzer) Analyze(fileMap extractor.FileMap) (pkgs []analyzer.Package, err error) {
	if !utils.IsCommandAvailable("rpm") {
		return nil, types.ErrNoRpmCmd
	}
	var parsedPkgs []analyzer.Package
	detected := false
	for _, filename := range a.RequiredFiles() {
		file, ok := fileMap[filename]
		if !ok {
			continue
		}
		parsedPkgs, err = a.parsePkgInfo(file)
		pkgs = append(pkgs, parsedPkgs...)
		detected = true
	}
	if !detected {
		return pkgs, analyzer.ErrNoPkgsDetected
	}
	if err != nil {
		return nil, xerrors.Errorf("failed to parse the pkg info: %w", err)
	}
	return pkgs, nil
}

func (a rpmCmdPkgAnalyzer) parsePkgInfo(packageBytes []byte) (pkgs []analyzer.Package, err error) {
	tmpDir, err := ioutil.TempDir("", "rpm")
	defer os.RemoveAll(tmpDir)
	if err != nil {
		return nil, xerrors.Errorf("failed to create a temp dir: %w", err)
	}

	filename := filepath.Join(tmpDir, "Packages")
	err = ioutil.WriteFile(filename, packageBytes, 0700)
	if err != nil {
		return nil, xerrors.Errorf("failed to write a package file: %w", err)
	}

	// rpm-python 4.11.3 rpm-4.11.3-35.el7.src.rpm
	// Extract binary package names because RHSA refers to binary package names.
	out, err := outputPkgInfo(tmpDir)
	if err != nil {
		return nil, xerrors.Errorf("failed to extract the package list: %w", err)
	}

	pkgString := string(out)

	scanner := bufio.NewScanner(strings.NewReader(pkgString))
	for scanner.Scan() {
		pkg, err := parseRPMOutput(scanner.Text())
		if err != nil {
			return nil, xerrors.Errorf("failed to parse the package list: %w", err)
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs, nil
}

func parseRPMOutput(line string) (pkg analyzer.Package, err error) {
	fields := strings.Fields(line)
	if len(fields) != 7 {
		return pkg, xerrors.Errorf("Failed to parse package line: %s", line)
	}

	var epoch int
	epochStr := fields[1]
	if epochStr == "0" || epochStr == "(none)" {
		epoch = 0
	} else {
		epoch, err = strconv.Atoi(epochStr)
		if err != nil {
			return pkg, xerrors.Errorf("failed to convert epoch from string to int", err)
		}
	}

	// parse source rpm
	var srcName, srcVer, srcRel string
	if fields[4] != "(none)" {
		// source epoch is not included in SOURCERPM
		srcName, srcVer, srcRel, _, _ = splitFileName(fields[4])
	}

	var moduleName, moduleStream, moduleVersion, moduleContext string
	if fields[6] != "(none)" {
		moduleName, moduleStream, moduleVersion, moduleContext = splitModularityLabel(fields[6])
	}

	return analyzer.Package{
		Name:          fields[0],
		Epoch:         epoch,
		Version:       fields[2],
		Release:       fields[3],
		Arch:          fields[5],
		SrcName:       srcName,
		SrcVersion:    srcVer,
		SrcRelease:    srcRel,
		SrcEpoch:      epoch, // NOTE: use epoch of binary package as epoch of src package
		ModuleName:    moduleName,
		ModuleStream:  moduleStream,
		ModuleVersion: moduleVersion,
		ModuleContext: moduleContext,
	}, nil
}

func outputPkgInfo(dir string) (out []byte, err error) {
	const oldFmt = "%{NAME} %{EPOCH} %{VERSION} %{RELEASE} %{SOURCERPM} %{ARCH} (none)\n"
	const newFmt = "%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{SOURCERPM} %{ARCH} (none)\n"
	const modularityFmt = "%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{SOURCERPM} %{ARCH} %{RPMTAG_MODULARITYLABEL}\n"

	// newest format order
	fmts := []string{modularityFmt, newFmt, oldFmt}
	for _, fmt := range fmts {
		var stdout bytes.Buffer
		command := exec.Command("rpm", "--dbpath", dir, "-qa", "--qf", fmt)
		command.Stderr = &stdout
		out, err = command.Output()
		if err != nil {
			return nil, RPMCommandError
		}
		if len(stdout.Bytes()) != 0 {
			continue
		}
		return out, nil
	}
	return out, nil
}

// ModularityLabel format is {module_name}:{module_stream}:{module_version}:{module_context}
func splitModularityLabel(moduleLabel string) (name, stream, version, context string) {
	ss := strings.Split(moduleLabel, ":")
	if len(ss) != 4 {
		return
	}
	return ss[0], ss[1], ss[2], ss[3]
}

// splitFileName returns a name, version, release, epoch, arch, e.g.::
//    foo-1.0-1.i386.rpm returns foo, 1.0, 1, i386
//    1:bar-9-123a.ia64.rpm returns bar, 9, 123a, 1, ia64
// https://github.com/rpm-software-management/yum/blob/043e869b08126c1b24e392f809c9f6871344c60d/rpmUtils/miscutils.py#L301
func splitFileName(filename string) (name, ver, rel string, epoch int, arch string) {
	if strings.HasSuffix(filename, ".rpm") {
		filename = filename[:len(filename)-4]
	}

	archIndex := strings.LastIndex(filename, ".")
	arch = filename[archIndex+1:]

	relIndex := strings.LastIndex(filename[:archIndex], "-")
	rel = filename[relIndex+1 : archIndex]

	verIndex := strings.LastIndex(filename[:relIndex], "-")
	ver = filename[verIndex+1 : relIndex]

	epochIndex := strings.Index(filename, ":")
	if epochIndex == -1 {
		epoch = 0
	} else {
		epoch, _ = strconv.Atoi(filename[:epochIndex])
	}

	name = filename[epochIndex+1 : verIndex]
	return name, ver, rel, epoch, arch
}

func (a rpmCmdPkgAnalyzer) RequiredFiles() []string {
	return []string{
		"usr/lib/sysimage/rpm/Packages",
		"var/lib/rpm/Packages",
	}
}
