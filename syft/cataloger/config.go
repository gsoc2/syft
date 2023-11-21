package cataloger

import (
	"crypto"
	"encoding/json"
	"fmt"

	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/source"
)

const (
	NoFilesSelection    FileCatalogingSelection = "no-files"
	OwnedFilesSelection FileCatalogingSelection = "owned-files"
	AllFilesSelection   FileCatalogingSelection = "all-files"
)

type FileCatalogingSelection string

type Config struct {
	Search         SearchConfig         `yaml:"search" json:"search" mapstructure:"search"`
	Files          FileCatalogingConfig `yaml:"files" json:"files" mapstructure:"files"`
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

type FileCatalogingConfig struct {
	Selection FileCatalogingSelection `yaml:"selection" json:"selection" mapstructure:"selection"`
	Hashers   []crypto.Hash           `yaml:"hashers" json:"hashers" mapstructure:"hashers"`
}

type fileCatalogingConfigMarshaledForm struct {
	Selection FileCatalogingSelection `yaml:"selection" json:"selection" mapstructure:"selection"`
	Hashers   []string                `yaml:"hashers" json:"hashers" mapstructure:"hashers"`
}

func (cfg FileCatalogingConfig) MarshalJSON() ([]byte, error) {
	marshaled := fileCatalogingConfigMarshaledForm{
		Selection: cfg.Selection,
		Hashers:   hashersToString(cfg.Hashers),
	}
	return json.Marshal(marshaled)
}

func hashersToString(hashers []crypto.Hash) []string {
	var result []string
	for _, h := range hashers {
		result = append(result, h.String())
	}
	return result
}

func (cfg *FileCatalogingConfig) UnmarshalJSON(data []byte) error {
	var marshaled fileCatalogingConfigMarshaledForm
	if err := json.Unmarshal(data, &marshaled); err != nil {
		return err
	}

	hashers, err := file.Hashers(marshaled.Hashers...)
	if err != nil {
		return fmt.Errorf("unable to parse configured hashers: %w", err)
	}
	cfg.Selection = marshaled.Selection
	cfg.Hashers = hashers
	return nil
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
		Files:          DefaultFilesConfig(),
		Relationships:  DefaultRelationshipsConfig(),
		DataGeneration: DefaultDataSynthesisConfig(),
	}
}

func DefaultSearchConfig() SearchConfig {
	return SearchConfig{
		Scope: source.SquashedScope,
	}
}

func DefaultFilesConfig() FileCatalogingConfig {
	hashers, err := file.Hashers("sha256")
	if err != nil {
		log.WithFields("error", err).Warn("unable to create file hashers")
	}
	return FileCatalogingConfig{
		Selection: OwnedFilesSelection,
		Hashers:   hashers,
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
