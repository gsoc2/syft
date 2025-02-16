package integration

import (
	"testing"

	"github.com/gsoc2/syft/syft/pkg"
	"github.com/gsoc2/syft/syft/source"
)

func TestMarinerDistroless(t *testing.T) {
	sbom, _ := catalogFixtureImage(t, "image-mariner-distroless", source.SquashedScope, nil)

	expectedPkgs := 12
	actualPkgs := 0
	for range sbom.Artifacts.Packages.Enumerate(pkg.RpmPkg) {
		actualPkgs += 1
	}

	if actualPkgs != expectedPkgs {
		t.Errorf("unexpected number of RPM packages: %d != %d", expectedPkgs, actualPkgs)
	}
}
