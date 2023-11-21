package task

import (
	"sync"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// SBOMBuilder provides a simple facade for simple additions to the SBOM
type SBOMBuilder interface {
	// nodes

	AddPackages(...pkg.Package)
	AddFileMetadata(file.Coordinates, file.Metadata)
	AddFileDigests(file.Coordinates, ...file.Digest)
	AddFileContents(file.Coordinates, string)
	AddFileLicenses(file.Coordinates, ...file.License)

	// edges

	AddRelationships(...artifact.Relationship)

	// other

	SetLinuxDistribution(linux.Release)
}

// SBOMAccessor allows for low-level access to the SBOM
type SBOMAccessor interface {
	WriteToSBOM(func(*sbom.SBOM))
	ReadFromSBOM(func(*sbom.SBOM))
}

type sbomBuilder struct {
	sbom *sbom.SBOM
	lock *sync.RWMutex
}

func NewSBOMBuilder(s *sbom.SBOM) SBOMBuilder {
	return &sbomBuilder{
		sbom: s,
		lock: &sync.RWMutex{},
	}
}

func (b sbomBuilder) WriteToSBOM(fn func(*sbom.SBOM)) {
	b.lock.Lock()
	defer b.lock.Unlock()

	fn(b.sbom)
}

func (b sbomBuilder) ReadFromSBOM(fn func(*sbom.SBOM)) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	fn(b.sbom)
}

func (b sbomBuilder) AddPackages(p ...pkg.Package) {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.sbom.Artifacts.Packages.Add(p...)
}

func (b sbomBuilder) AddFileMetadata(coordinates file.Coordinates, metadata file.Metadata) {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.sbom.Artifacts.FileMetadata[coordinates] = metadata
}

func (b sbomBuilder) AddFileDigests(coordinates file.Coordinates, digest ...file.Digest) {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.sbom.Artifacts.FileDigests[coordinates] = append(b.sbom.Artifacts.FileDigests[coordinates], digest...)
}

func (b sbomBuilder) AddFileContents(coordinates file.Coordinates, s string) {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.sbom.Artifacts.FileContents[coordinates] = s
}

func (b sbomBuilder) AddFileLicenses(coordinates file.Coordinates, license ...file.License) {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.sbom.Artifacts.FileLicenses[coordinates] = append(b.sbom.Artifacts.FileLicenses[coordinates], license...)
}

func (b sbomBuilder) AddRelationships(relationship ...artifact.Relationship) {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.sbom.Relationships = append(b.sbom.Relationships, relationship...)
}

func (b sbomBuilder) SetLinuxDistribution(release linux.Release) {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.sbom.Artifacts.LinuxDistribution = &release
}
