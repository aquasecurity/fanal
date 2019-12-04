package utils

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

var (
	PathSeparator = fmt.Sprintf("%c", os.PathSeparator)
)

func CacheDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "fanal")
	return dir
}

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func IsCommandAvailable(name string) bool {
	if _, err := exec.LookPath(name); err != nil {
		return false
	}
	return true
}

func IsGzip(f *bufio.Reader) bool {
	buf := make([]byte, 3)
	buf, err := f.Peek(3)
	if err != nil {
		return false
	}
	return buf[0] == 0x1F && buf[1] == 0x8B && buf[2] == 0x8
}
