package cache

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
)

func TestSetAndGet(t *testing.T) {
	d, _ := ioutil.TempDir("", "TestGetDir-*")
	f, _ := ioutil.TempFile(d, "foo.bar.baz-*")

	oldCacheDir := cacheDir
	defer func() {
		cacheDir = oldCacheDir
		_ = os.RemoveAll(d)
	}()
	cacheDir = d

	// set
	expectedCacheContents := "foo bar baz"
	var buf bytes.Buffer
	buf.Write([]byte(expectedCacheContents))

	r, err := Set(f.Name(), &buf)
	assert.NoError(t, err)

	b, _ := ioutil.ReadAll(r)
	assert.Equal(t, expectedCacheContents, string(b))


	// get
	actualFile := Get(f.Name())
	actualBytes, _ := ioutil.ReadAll(actualFile)
	assert.Equal(t, expectedCacheContents, string(actualBytes))
}