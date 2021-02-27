package walker

import (
	"testing"

	"github.com/aquasecurity/fanal/analyzer/library"

	"github.com/stretchr/testify/assert"
)

func Test_isIgnore(t *testing.T) {
	for _, fp := range []string{`foo\.git`, `foo\node_modules`} {
		assert.True(t, isIgnored(fp))
	}
}
