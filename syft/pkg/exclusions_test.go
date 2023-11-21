package pkg

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
)

func TestExclude(t *testing.T) {
	packageA := Package{Name: "package-a", Type: ApkPkg}
	packageB := Package{Name: "package-a", Type: PythonPkg}
	packageC := Package{Name: "package-a", Type: BinaryPkg}
	packageD := Package{Name: "package-d", Type: BinaryPkg}
	for _, p := range []*Package{&packageA, &packageB, &packageC, &packageD} {
		p := p
		p.SetID()
	}

	tests := []struct {
		name          string
		relationship  artifact.Relationship
		packages      *Collection
		shouldExclude bool
	}{
		{
			name: "no exclusions from os -> python",
			relationship: artifact.Relationship{
				Type: artifact.OwnershipByFileOverlapRelationship,
				From: packageA,
				To:   packageB,
			},
			packages:      NewCollection(packageA, packageB),
			shouldExclude: false,
		},
		{
			name: "exclusions from os -> binary",
			relationship: artifact.Relationship{
				Type: artifact.OwnershipByFileOverlapRelationship,
				From: packageA,
				To:   packageC,
			},
			packages:      NewCollection(packageA, packageC),
			shouldExclude: true,
		},
		{
			name: "no exclusions from python -> binary",
			relationship: artifact.Relationship{
				Type: artifact.OwnershipByFileOverlapRelationship,
				From: packageB,
				To:   packageC,
			},
			packages:      NewCollection(packageB, packageC),
			shouldExclude: false,
		},
		{
			name: "no exclusions for different package names",
			relationship: artifact.Relationship{
				Type: artifact.OwnershipByFileOverlapRelationship,
				From: packageA,
				To:   packageD,
			},
			packages:      NewCollection(packageA, packageD),
			shouldExclude: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !ExcludeBinaryByFileOwnershipOverlap(test.relationship, test.packages) && test.shouldExclude {
				t.Errorf("expected to exclude relationship %+v", test.relationship)
			}
		})

	}
}
