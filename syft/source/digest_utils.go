package source

import (
	"strings"

	"github.com/gsoc2/syft/syft/artifact"
)

func artifactIDFromDigest(input string) artifact.ID {
	return artifact.ID(strings.TrimPrefix(input, "sha256:"))
}
