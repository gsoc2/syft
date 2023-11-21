package java

import "github.com/anchore/syft/syft/cataloger"

const mavenBaseURL = "https://repo1.maven.org/maven2"

type CatalogerConfig struct {
	cataloger.ArchiveSearchConfig `yaml:",inline" json:"" mapstructure:",squash"`
	UseNetwork                    bool   `yaml:"use-network" json:"use-network" mapstructure:"use-network"`
	MavenBaseURL                  string `yaml:"maven-base-url" json:"maven-base-url" mapstructure:"maven-base-url"`
	MaxParentRecursiveDepth       int    `yaml:"max-parent-recursive-depth" json:"max-parent-recursive-depth" mapstructure:"max-parent-recursive-depth"`
}

func (j CatalogerConfig) WithUseNetwork(input bool) CatalogerConfig {
	j.UseNetwork = input
	return j
}

func (j CatalogerConfig) WithMavenCentralURL(input string) CatalogerConfig {
	if input != "" {
		j.MavenBaseURL = input
	}
	return j
}

func (j CatalogerConfig) WithArchiveTraversal(search cataloger.ArchiveSearchConfig, maxDepth int) CatalogerConfig {
	if maxDepth > 0 {
		j.MaxParentRecursiveDepth = maxDepth
	}
	j.ArchiveSearchConfig = search
	return j
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{
		ArchiveSearchConfig: cataloger.ArchiveSearchConfig{
			IncludeIndexedArchives:   true,
			IncludeUnindexedArchives: false,
		},
		UseNetwork:              false,
		MavenBaseURL:            mavenBaseURL,
		MaxParentRecursiveDepth: 5,
	}
}
