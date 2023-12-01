package githubactions

import (
	"testing"

	"github.com/gsoc2/syft/syft/artifact"
	"github.com/gsoc2/syft/syft/file"
	"github.com/gsoc2/syft/syft/pkg"
	"github.com/gsoc2/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_parseCompositeActionForActionUsage(t *testing.T) {
	fixture := "test-fixtures/composite-action.yaml"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation(fixture).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

	expected := []pkg.Package{
		{
			Name:      "actions/setup-go",
			Version:   "v4",
			Type:      pkg.GithubActionPkg,
			Locations: fixtureLocationSet,
			PURL:      "pkg:github/actions/setup-go@v4",
		},
		{
			Name:      "actions/cache",
			Version:   "v3",
			Type:      pkg.GithubActionPkg,
			Locations: fixtureLocationSet,
			PURL:      "pkg:github/actions/cache@v3",
		},
	}

	var expectedRelationships []artifact.Relationship
	pkgtest.TestFileParser(t, fixture, parseCompositeActionForActionUsage, expected, expectedRelationships)
}
