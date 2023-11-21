package cataloging

import (
	"github.com/anchore/syft/syft/source"
)

type Config struct {
	Search         SearchConfig         `yaml:"search" json:"search" mapstructure:"search"`
	Relationships  RelationshipsConfig  `yaml:"relationships" json:"relationships" mapstructure:"relationships"`
	DataGeneration DataGenerationConfig `yaml:"data-generation" json:"data-generation" mapstructure:"data-generation"`
}

type SearchConfig struct {
	Scope source.Scope `yaml:"scope" json:"scope" mapstructure:"scope"`
}

type ArchiveSearchConfig struct {
	IncludeIndexedArchives   bool `yaml:"include-indexed-archives" json:"include-indexed-archives" mapstructure:"include-indexed-archives"`
	IncludeUnindexedArchives bool `yaml:"include-unindexed-archives" json:"include-unindexed-archives" mapstructure:"include-unindexed-archives"`
}

type RelationshipsConfig struct {
	FileOwnership                                 bool `yaml:"file-ownership" json:"file-ownership" mapstructure:"file-ownership"`
	FileOwnershipOverlap                          bool `yaml:"file-ownership-overlap" json:"file-ownership-overlap" mapstructure:"file-ownership-overlap"`
	ExcludeBinaryPackagesWithFileOwnershipOverlap bool `yaml:"exclude-binary-packages-with-file-ownership-overlap" json:"exclude-binary-packages-with-file-ownership-overlap" mapstructure:"exclude-binary-packages-with-file-ownership-overlap"`
}

type DataGenerationConfig struct {
	GenerateCPEs          bool `yaml:"generate-cpes" json:"generate-cpes" mapstructure:"generate-cpes"`
	GuessLanguageFromPURL bool `yaml:"guess-language-from-purl" json:"guess-language-from-purl" mapstructure:"guess-language-from-purl"`
}

func DefaultConfig() Config {
	return Config{
		Search:         DefaultSearchConfig(),
		Relationships:  DefaultRelationshipsConfig(),
		DataGeneration: DefaultDataSynthesisConfig(),
	}
}

func DefaultSearchConfig() SearchConfig {
	return SearchConfig{
		Scope: source.SquashedScope,
	}
}

func DefaultRelationshipsConfig() RelationshipsConfig {
	return RelationshipsConfig{
		FileOwnership:        true,
		FileOwnershipOverlap: true,
		ExcludeBinaryPackagesWithFileOwnershipOverlap: true,
	}
}

func DefaultDataSynthesisConfig() DataGenerationConfig {
	return DataGenerationConfig{
		GenerateCPEs:          true,
		GuessLanguageFromPURL: true,
	}
}
