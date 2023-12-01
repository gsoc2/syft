package integration

import (
	"testing"

	"github.com/gsoc2/syft/syft/source"
)

func TestRegressionJavaNoMainPackage(t *testing.T) { // Regression: https://github.com/gsoc2/syft/issues/252
	catalogFixtureImage(t, "image-java-no-main-package", source.SquashedScope, nil)
}
