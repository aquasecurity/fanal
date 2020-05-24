package artifact

import (
	"context"

	"github.com/aquasecurity/fanal/types"
)

type Artifact interface {
	Inspect(ctx context.Context) (types.ArtifactReference, error)
}
