package cataloger

import (
	"github.com/gsoc2/syft/syft/cataloging"
	"github.com/gsoc2/syft/syft/pkg/cataloger/golang"
	"github.com/gsoc2/syft/syft/pkg/cataloger/java"
	"github.com/gsoc2/syft/syft/pkg/cataloger/kernel"
	"github.com/gsoc2/syft/syft/pkg/cataloger/python"
)

// TODO: these field naming vs helper function naming schemes are inconsistent.
type Config struct {
	Search                          SearchConfig
	Golang                          golang.CatalogerConfig
	LinuxKernel                     kernel.LinuxKernelCatalogerConfig
	Python                          python.CatalogerConfig
	Java                            java.ArchiveCatalogerConfig
	Catalogers                      []string
	Parallelism                     int
	ExcludeBinaryOverlapByOwnership bool
}

func DefaultConfig() Config {
	return Config{
		Search:                          DefaultSearchConfig(),
		Parallelism:                     1,
		LinuxKernel:                     kernel.DefaultLinuxCatalogerConfig(),
		Python:                          python.DefaultCatalogerConfig(),
		Java:                            java.DefaultArchiveCatalogerConfig(),
		ExcludeBinaryOverlapByOwnership: true,
	}
}

// JavaConfig merges relevant config values from Config to return a java.Config struct.
// Values like IncludeUnindexedArchives and IncludeIndexedArchives are used across catalogers
// and are not specific to Java requiring this merge.
func (c Config) JavaConfig() java.ArchiveCatalogerConfig {
	return java.ArchiveCatalogerConfig{
		ArchiveSearchConfig: cataloging.ArchiveSearchConfig{
			IncludeUnindexedArchives: c.Search.IncludeUnindexedArchives,
			IncludeIndexedArchives:   c.Search.IncludeIndexedArchives,
		},
		UseNetwork:              c.Java.UseNetwork,
		MavenBaseURL:            c.Java.MavenBaseURL,
		MaxParentRecursiveDepth: c.Java.MaxParentRecursiveDepth,
	}
}
