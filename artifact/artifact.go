package artifact

import (
	"context"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

type InspectOption struct {
	DisableAnalyzers []analyzer.Type
}

type Artifact interface {
	Inspect(ctx context.Context, option InspectOption) (reference types.ArtifactReference, err error)
}
