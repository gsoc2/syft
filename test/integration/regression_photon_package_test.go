package integration

import (
	"testing"

	"github.com/gsoc2/syft/syft/pkg"
	"github.com/gsoc2/syft/syft/source"
)

func TestPhotonPackageRegression(t *testing.T) { // Regression: https://github.com/gsoc2/syft/pull/1997
	sbom, _ := catalogFixtureImage(t, "image-photon-all-layers", source.AllLayersScope, nil)
	var packages []pkg.Package
	for p := range sbom.Artifacts.Packages.Enumerate() {
		packages = append(packages, p)
	}

	if len(packages) < 1 {
		t.Errorf("failed to find packages for photon distro; wanted > 0 got 0")
	}
}
