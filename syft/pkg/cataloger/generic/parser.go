package generic

import (
	"github.com/gsoc2/syft/syft/artifact"
	"github.com/gsoc2/syft/syft/file"
	"github.com/gsoc2/syft/syft/linux"
	"github.com/gsoc2/syft/syft/pkg"
)

type Environment struct {
	LinuxRelease *linux.Release
}

type Parser func(file.Resolver, *Environment, file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error)
