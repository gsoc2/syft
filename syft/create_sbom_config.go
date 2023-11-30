package syft

import (
	"fmt"
	"strings"

	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// CreateSBOMConfig specifies all parameters needed for creating an SBOM
type CreateSBOMConfig struct {
	// required configuration input to specify how cataloging should be performed
	CatalogerConfig                 cataloging.Config
	PackagesConfig                  pkgcataloging.Config
	FilesConfig                     filecataloging.Config
	Parallelism                     int
	CatalogerSelectionBasedOnSource bool
	CatalogerSelectionExpressions   []string

	// audit what tool is being used to generate the SBOM
	ToolName          string
	ToolVersion       string
	ToolConfiguration interface{}

	// user provided cataloging objects
	packageTaskFactories task.PackageTaskFactories
}

func DefaultCreateSBOMConfig() CreateSBOMConfig {
	return CreateSBOMConfig{
		CatalogerConfig:                 cataloging.DefaultConfig(),
		PackagesConfig:                  pkgcataloging.DefaultConfig(),
		FilesConfig:                     filecataloging.DefaultConfig(),
		CatalogerSelectionBasedOnSource: true,
		Parallelism:                     1,
		packageTaskFactories:            task.DefaultPackageTaskFactories(),
	}
}

func (c CreateSBOMConfig) WithTool(name, version string, cfg ...any) CreateSBOMConfig {
	c.ToolName = name
	c.ToolVersion = version
	c.ToolConfiguration = cfg
	return c
}

func (c CreateSBOMConfig) WithParallelism(p int) CreateSBOMConfig {
	if p < 1 {
		// TODO: warn?
		p = 1
	}
	c.Parallelism = p
	return c
}

func (c CreateSBOMConfig) WithCatalogingConfig(cfg cataloging.Config) CreateSBOMConfig {
	c.CatalogerConfig = cfg
	return c
}

func (c CreateSBOMConfig) WithPackagesConfig(cfg pkgcataloging.Config) CreateSBOMConfig {
	c.PackagesConfig = cfg
	return c
}

func (c CreateSBOMConfig) WithFilesConfig(cfg filecataloging.Config) CreateSBOMConfig {
	c.FilesConfig = cfg
	return c
}

func (c CreateSBOMConfig) WithNoFiles() CreateSBOMConfig {
	c.FilesConfig = filecataloging.Config{
		Selection: file.NoFilesSelection,
		Hashers:   nil,
	}
	return c
}

func (c CreateSBOMConfig) WithCatalogerSelectionBasedOnSource(value bool) CreateSBOMConfig {
	c.CatalogerSelectionBasedOnSource = value
	return c
}

func (c CreateSBOMConfig) WithCatalogerSelection(expressions ...string) CreateSBOMConfig {
	c.CatalogerSelectionExpressions = nil
	for _, expr := range expressions {
		var cleaned []string
		for _, tag := range strings.Split(expr, ",") {
			tag = strings.TrimSpace(tag)
			if tag == "" {
				continue
			}
			cleaned = append(cleaned, tag)
		}
		c.CatalogerSelectionExpressions = append(c.CatalogerSelectionExpressions, strings.Join(cleaned, ","))
	}

	return c
}

func (c CreateSBOMConfig) WithNoCatalogers() CreateSBOMConfig {
	c.packageTaskFactories = nil
	return c
}

func (c CreateSBOMConfig) WithCatalogers(catalogers ...pkg.Cataloger) CreateSBOMConfig {
	for _, cat := range catalogers {
		c = c.WithCataloger(cat)
	}

	return c
}

func (c CreateSBOMConfig) WithCataloger(cat pkg.Cataloger, tags ...string) CreateSBOMConfig {
	c.packageTaskFactories = append(c.packageTaskFactories,
		func(cfg cataloging.Config, pkgsCfg pkgcataloging.Config) task.Task {
			return task.NewPackageTask(cfg, cat, tags...)
		},
	)

	return c
}

func (c CreateSBOMConfig) finalTaskGroups(src source.Description) ([][]task.Task, *catalogerManifest, error) {
	var taskGroups [][]task.Task

	// generate package and file tasks based on the configuration
	fileTasks := c.fileTasks()
	pkgTasks, request, err := c.packageTasks(src)
	if err != nil {
		return nil, nil, err
	}

	// combine the user-provided and configured tasks
	if c.FilesConfig.Selection == file.OwnedFilesSelection {
		// special case: we need the package info when we are cataloging files owned by packages
		taskGroups = append(taskGroups, pkgTasks, fileTasks)
	} else {
		taskGroups = append(taskGroups, append(pkgTasks, fileTasks...))
	}

	return taskGroups, &catalogerManifest{
		Requested:      request,
		CatalogersUsed: formatTaskNames(pkgTasks),
	}, nil
}

func (c CreateSBOMConfig) fileTasks() []task.Task {
	var fileTasks []task.Task

	if t := task.NewFileDigestCatalogerTask(c.FilesConfig.Selection, c.FilesConfig.Hashers...); t != nil {
		fileTasks = append(fileTasks, t)
	}
	if t := task.NewFileMetadataCatalogerTask(c.FilesConfig.Selection); t != nil {
		fileTasks = append(fileTasks, t)
	}
	return fileTasks
}

func (c CreateSBOMConfig) packageTasks(src source.Description) ([]task.Task, []string, error) {
	pkgTasks, err := c.packageTaskFactories.Tasks(c.CatalogerConfig, c.PackagesConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create package cataloger tasks: %w", err)
	}

	var basis string
	if c.CatalogerSelectionBasedOnSource {
		switch m := src.Metadata.(type) {
		case source.StereoscopeImageSourceMetadata:
			basis = task.ImageTag
		case source.FileSourceMetadata, source.DirectorySourceMetadata:
			basis = task.DirectoryTag
		default:
			return nil, nil, fmt.Errorf("unable to determine cataloger defaults for source: %T", m)
		}
	}

	return task.Select(pkgTasks, basis, c.CatalogerSelectionExpressions...)
}

func (c CreateSBOMConfig) validate() error {
	if c.CatalogerConfig.Relationships.ExcludeBinaryPackagesWithFileOwnershipOverlap {
		if !c.CatalogerConfig.Relationships.FileOwnershipOverlap {
			return fmt.Errorf("invalid configuration: to exclude binary packages based on file ownership overlap relationships, cataloging file ownership overlap relationships must be enabled")
		}
	}
	return nil
}

func (c CreateSBOMConfig) Create(src source.Source) (*sbom.SBOM, error) {
	return CreateSBOM(src, c)
}
