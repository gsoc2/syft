package options

import (
	"fmt"
	"strings"

	"github.com/iancoleman/strcase"
	"github.com/mitchellh/go-homedir"

	"github.com/anchore/clio"
	"github.com/anchore/fangs"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloger"
	pkgCataloger "github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/pkg/cataloger/kernel"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
	"github.com/anchore/syft/syft/source"
)

type Catalog struct {
	// high-level cataloger configuration
	Catalogers  []string `yaml:"catalogers" json:"catalogers" mapstructure:"catalogers"`
	Package     pkg      `yaml:"package" json:"package" mapstructure:"package"`
	File        file     `yaml:"file" json:"file" mapstructure:"file"`
	Scope       string   `yaml:"scope" json:"scope" mapstructure:"scope"`
	Parallelism int      `yaml:"parallelism" json:"parallelism" mapstructure:"parallelism"` // the number of catalog workers to run in parallel

	// ecosystem-specific cataloger configuration
	Golang      golangConfig `yaml:"golang" json:"golang" mapstructure:"golang"`
	Java        javaConfig   `yaml:"java" json:"java" mapstructure:"java"`
	LinuxKernel linuxKernel  `yaml:"linux-kernel" json:"linux-kernel" mapstructure:"linux-kernel"`
	Python      pythonConfig `yaml:"python" json:"python" mapstructure:"python"`

	// configuration for the source (the subject being analyzed)
	Registry   registry     `yaml:"registry" json:"registry" mapstructure:"registry"`
	Platform   string       `yaml:"platform" json:"platform" mapstructure:"platform"`
	Name       string       `yaml:"name" json:"name" mapstructure:"name"` // deprecated
	Source     sourceConfig `yaml:"source" json:"source" mapstructure:"source"`
	Exclusions []string     `yaml:"exclude" json:"exclude" mapstructure:"exclude"`
}

var _ interface {
	clio.FlagAdder
	clio.PostLoader
} = (*Catalog)(nil)

func DefaultCatalog() Catalog {
	return Catalog{
		Scope:       source.SquashedScope.String(),
		Package:     defaultPkg(),
		LinuxKernel: defaultLinuxKernel(),
		File:        defaultFile(),
		Source:      defaultSourceCfg(),
		Parallelism: 1,
	}
}

func (cfg Catalog) ToCatalogerConfig() cataloger.Config {
	hashers, err := intFile.Hashers(cfg.File.Metadata.Digests...)
	if err != nil {
		log.WithFields("error", err).Warn("unable to configure file hashers")
	}

	return cataloger.Config{
		Search: cataloger.SearchConfig{
			Scope: source.ParseScope(cfg.Scope),
		},
		Relationships: cataloger.RelationshipsConfig{
			FileOwnership:        true,  // TODO: tie to app config
			FileOwnershipOverlap: false, // TODO: tie to app config
			ExcludeBinaryPackagesWithFileOwnershipOverlap: cfg.Package.ExcludeBinaryOverlapByOwnership,
		},
		DataGeneration: cataloger.DataGenerationConfig{
			GenerateCPEs:          true, // TODO: tie to app config
			GuessLanguageFromPURL: true, // TODO: tie to app config
		},
		Files: cataloger.FileCatalogingConfig{
			Selection: cfg.File.Metadata.Selection,
			Hashers:   hashers,
		},
		// TODO...
		//Catalogers:  cfg.Catalogers,
	}
}

func (cfg Catalog) ToSBOMConfig(id clio.Identification) *syft.SBOMConfig {
	return syft.DefaultSBOMConfig().
		WithTool(id.Name, id.Version).
		WithParallelism(cfg.Parallelism).
		WithCatalogerConfig(cfg.ToCatalogerConfig()).
		WithPackagesConfig(cfg.ToPackagesConfig()).
		WithCatalogerSelectionBasedOnSource(true).
		WithCatalogerSelection(cfg.Catalogers...)
}

func (cfg Catalog) ToPackagesConfig() pkgCataloger.Config {
	archiveSearch := cataloger.ArchiveSearchConfig{
		IncludeIndexedArchives:   cfg.Package.SearchIndexedArchives,
		IncludeUnindexedArchives: cfg.Package.SearchUnindexedArchives,
	}
	return pkgCataloger.Config{
		Golang: golang.DefaultCatalogerConfig().
			WithSearchLocalModCacheLicenses(cfg.Golang.SearchLocalModCacheLicenses).
			WithLocalModCacheDir(cfg.Golang.LocalModCacheDir).
			WithSearchRemoteLicenses(cfg.Golang.SearchRemoteLicenses).
			WithProxy(cfg.Golang.Proxy).
			WithNoProxy(cfg.Golang.NoProxy),
		LinuxKernel: kernel.LinuxKernelCatalogerConfig{
			CatalogModules: cfg.LinuxKernel.CatalogModules,
		},
		Python: python.CatalogerConfig{
			GuessUnpinnedRequirements: cfg.Python.GuessUnpinnedRequirements,
		},
		Java: java.DefaultCatalogerConfig().
			WithUseNetwork(cfg.Java.UseNetwork).
			WithMavenCentralURL(cfg.Java.MavenURL).
			WithArchiveTraversal(archiveSearch, cfg.Java.MaxParentRecursiveDepth),
	}
}

func (cfg *Catalog) AddFlags(flags clio.FlagSet) {
	var validScopeValues []string
	for _, scope := range source.AllScopes {
		validScopeValues = append(validScopeValues, strcase.ToDelimited(string(scope), '-'))
	}
	flags.StringVarP(&cfg.Scope, "scope", "s",
		fmt.Sprintf("selection of layers to catalog, options=%v", validScopeValues))

	flags.StringVarP(&cfg.Platform, "platform", "",
		"an optional platform specifier for container image sources (e.g. 'linux/arm64', 'linux/arm64/v8', 'arm64', 'linux')")

	flags.StringArrayVarP(&cfg.Exclusions, "exclude", "",
		"exclude paths from being scanned using a glob expression")

	flags.StringArrayVarP(&cfg.Catalogers, "catalogers", "",
		"enable one or more package catalogers")

	flags.StringVarP(&cfg.Source.Name, "name", "",
		"set the name of the target being analyzed")

	if pfp, ok := flags.(fangs.PFlagSetProvider); ok {
		flagSet := pfp.PFlagSet()
		flagSet.Lookup("name").Deprecated = "use: source-name"
	}

	flags.StringVarP(&cfg.Source.Name, "source-name", "",
		"set the name of the target being analyzed")

	flags.StringVarP(&cfg.Source.Version, "source-version", "",
		"set the version of the target being analyzed")

	flags.StringVarP(&cfg.Source.BasePath, "base-path", "",
		"base directory for scanning, no links will be followed above this directory, and all paths will be reported relative to this directory")
}

func (cfg *Catalog) PostLoad() error {
	// parse options on this struct
	var catalogers []string
	for _, c := range cfg.Catalogers {
		for _, f := range strings.Split(c, ",") {
			catalogers = append(catalogers, strings.TrimSpace(f))
		}
	}
	cfg.Catalogers = catalogers

	if cfg.Name != "" {
		log.Warnf("name parameter is deprecated. please use: source-name. name will be removed in a future version")
		if cfg.Source.Name == "" {
			cfg.Source.Name = cfg.Name
		}
	}

	s := source.ParseScope(cfg.Scope)
	if s == source.UnknownScope {
		return fmt.Errorf("bad scope value %q", cfg.Scope)
	}

	return nil
}

func expandFilePath(file string) (string, error) {
	if file != "" {
		expandedPath, err := homedir.Expand(file)
		if err != nil {
			return "", fmt.Errorf("unable to expand file path=%q: %w", file, err)
		}
		file = expandedPath
	}
	return file, nil
}
