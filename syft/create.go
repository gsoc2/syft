package syft

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/scylladb/go-set/strset"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloger"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/internal/task"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	pkgCataloger "github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// apiConfiguration is an audit trail for what input configuration was used to generate the SBOM
type apiConfiguration struct {
	CatalogerConfig *cataloger.Config    `json:"catalog,omitempty" yaml:"catalog" mapstructure:"catalog"`
	PackagesConfig  *pkgCataloger.Config `json:"packages,omitempty" yaml:"packages" mapstructure:"packages"`
	Catalogers      catalogerManifest    `json:"catalogers" yaml:"catalogers" mapstructure:"catalogers"`
	ExtraConfigs    any                  `json:"extra,omitempty" yaml:"extra" mapstructure:"extra"`
}

type marshalAPIConfiguration apiConfiguration

func (cfg apiConfiguration) MarshalJSON() ([]byte, error) {
	// since the api configuration is placed into the SBOM in an empty interface, and we want a stable ordering of
	// keys (not guided by the struct ordering) we need to convert the struct to a map. This is best done with
	// simply marshalling and unmarshalling. Mapstructure is used to ensure we are honoring all json struct
	// tags. Once we have a map, we can lean on the stable ordering of json map keys in the stdlib. This is an
	// implementation detail that can be at least relied on until Go 2 (at which point it can change).
	// This dance allows us to guarantee ordering of keys in the configuration section of the SBOM.

	initialJSON, err := json.Marshal(marshalAPIConfiguration(cfg))
	if err != nil {
		return nil, err
	}

	var dataMap map[string]interface{}
	if err := json.Unmarshal(initialJSON, &dataMap); err != nil {
		return nil, err
	}

	return marshalSorted(dataMap)
}

// marshalSorted recursively marshals a map with sorted keys
func marshalSorted(m interface{}) ([]byte, error) {
	if reflect.TypeOf(m).Kind() != reflect.Map {
		return json.Marshal(m)
	}

	val := reflect.ValueOf(m)
	sortedMap := make(map[string]interface{})

	for _, key := range val.MapKeys() {
		value := val.MapIndex(key).Interface()

		if value != nil && reflect.TypeOf(value).Kind() == reflect.Map {
			sortedValue, err := marshalSorted(value)
			if err != nil {
				return nil, err
			}
			sortedMap[key.String()] = json.RawMessage(sortedValue)
		} else {
			sortedMap[key.String()] = value
		}
	}

	return json.Marshal(sortedMap)
}

type catalogerManifest struct {
	Requested      []string `json:"requested" yaml:"requested" mapstructure:"requested"`
	CatalogersUsed []string `json:"used" yaml:"used" mapstructure:"used"`
}

// SBOMConfig specifies all parameters needed for creating an SBOM
type SBOMConfig struct {
	// required configuration input to specify how cataloging should be performed
	CatalogerConfig                 *cataloger.Config
	PackagesConfig                  *pkgCataloger.Config
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

func DefaultSBOMConfig() *SBOMConfig {
	cfg := cataloger.DefaultConfig()
	pkgCfg := pkgCataloger.DefaultConfig()
	return &SBOMConfig{
		CatalogerConfig:                 &cfg,
		PackagesConfig:                  &pkgCfg,
		CatalogerSelectionBasedOnSource: true,
		Parallelism:                     1,
		packageTaskFactories:            task.DefaultPackageTaskFactories(),
	}
}

func (c *SBOMConfig) WithTool(name, version string, cfg ...any) *SBOMConfig {
	c.ToolName = name
	c.ToolVersion = version
	c.ToolConfiguration = cfg
	return c
}

func (c *SBOMConfig) WithParallelism(p int) *SBOMConfig {
	if p < 1 {
		// TODO: warn?
		p = 1
	}
	c.Parallelism = p
	return c
}

func (c *SBOMConfig) WithCatalogerConfig(cfg cataloger.Config) *SBOMConfig {
	c.CatalogerConfig = &cfg
	return c
}

func (c *SBOMConfig) WithPackagesConfig(cfg pkgCataloger.Config) *SBOMConfig {
	c.PackagesConfig = &cfg
	return c
}

func (c *SBOMConfig) WithCatalogerSelectionBasedOnSource(value bool) *SBOMConfig {
	c.CatalogerSelectionBasedOnSource = value
	return c
}

func (c *SBOMConfig) WithCatalogerSelection(expressions ...string) *SBOMConfig {
	c.CatalogerSelectionExpressions = nil
	for _, expr := range expressions {
		for _, tag := range strings.Split(expr, ",") {
			c.CatalogerSelectionExpressions = append(c.CatalogerSelectionExpressions, strings.TrimSpace(tag))
		}
	}

	return c
}

func (c *SBOMConfig) WithNoCatalogers() *SBOMConfig {
	c.packageTaskFactories = nil
	return c
}

func (c *SBOMConfig) WithCatalogers(catalogers ...pkg.Cataloger) *SBOMConfig {
	for _, cat := range catalogers {
		c = c.WithCataloger(cat)
	}

	return c
}

func (c *SBOMConfig) WithCataloger(cat pkg.Cataloger, tags ...string) *SBOMConfig {
	c.packageTaskFactories = append(c.packageTaskFactories,
		func(cfg cataloger.Config, pkgsCfg pkgCataloger.Config) task.Task {
			return task.NewPackageTask(cfg, cat, tags...)
		},
	)

	return c
}

func (c *SBOMConfig) finalTaskGroups(src source.Description) ([][]task.Task, *catalogerManifest, error) {
	var taskGroups [][]task.Task

	if c.CatalogerConfig == nil {
		return nil, nil, fmt.Errorf("cataloger config must be specified")
	}

	if c.PackagesConfig == nil {
		return nil, nil, fmt.Errorf("packages config must be specified when default catalogers are used")
	}

	// generate package and file tasks based on the configuration
	fileTasks := c.fileTasks()
	pkgTasks, request, err := c.packageTasks(src)
	if err != nil {
		return nil, nil, err
	}

	// combine the user-provided and configured tasks
	if c.CatalogerConfig.Files.Selection == cataloger.OwnedFilesSelection {
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

func (c *SBOMConfig) fileTasks() []task.Task {
	var fileTasks []task.Task

	if t := task.NewFileDigestCatalogerTask(c.CatalogerConfig.Files.Selection, c.CatalogerConfig.Files.Hashers...); t != nil {
		fileTasks = append(fileTasks, t)
	}
	if t := task.NewFileMetadataCatalogerTask(c.CatalogerConfig.Files.Selection); t != nil {
		fileTasks = append(fileTasks, t)
	}
	return fileTasks
}

func (c *SBOMConfig) packageTasks(src source.Description) ([]task.Task, []string, error) {
	pkgTasks, err := c.packageTaskFactories.Tasks(*c.CatalogerConfig, *c.PackagesConfig)
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

func (c *SBOMConfig) Create(src source.Source) (*sbom.SBOM, error) {
	return CreateSBOM(src, c)
}

// nolint:funlen
func CreateSBOM(src source.Source, cfg *SBOMConfig) (*sbom.SBOM, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cataloger config must be specified")
	}

	srcMetadata := src.Describe()

	taskGroups, audit, err := cfg.finalTaskGroups(srcMetadata)
	if err != nil {
		return nil, fmt.Errorf("unable to finalize task groups: %w", err)
	}

	resolver, err := src.FileResolver(cfg.CatalogerConfig.Search.Scope)
	if err != nil {
		return nil, fmt.Errorf("unable to get file resolver: %w", err)
	}

	s := sbom.SBOM{
		Source: srcMetadata,
		Descriptor: sbom.Descriptor{
			Name:    cfg.ToolName,
			Version: cfg.ToolVersion,
			Configuration: apiConfiguration{
				CatalogerConfig: cfg.CatalogerConfig,
				PackagesConfig:  cfg.PackagesConfig,
				Catalogers:      *audit,
				ExtraConfigs:    cfg.ToolConfiguration,
			},
		},
		Artifacts: sbom.Artifacts{
			Packages:          pkg.NewCollection(),
			LinuxDistribution: linux.IdentifyRelease(resolver),
		},
	}

	catalogingProgress := monitorCatalogingTask(src.ID(), taskGroups)
	packageCatalogingProgress := monitorPackageCatalogingTask()

	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		for {
			<-ticker.C

			count := humanize.Comma(int64(s.Artifacts.Packages.PackageCount()))
			packageCatalogingProgress.AtomicStage.Set(fmt.Sprintf("%s packages", count))

			if progress.IsCompleted(packageCatalogingProgress) {
				break
			}
		}
	}()

	builder := task.NewSBOMBuilder(&s)
	for i := range taskGroups {
		err := task.NewTaskExecutor(taskGroups[i], cfg.Parallelism).Execute(resolver, builder, catalogingProgress)
		if err != nil {
			return nil, fmt.Errorf("failed to run tasks: %w", err)
		}
	}

	packageCatalogingProgress.SetCompleted()
	catalogingProgress.SetCompleted()

	// always add package to package relationships last
	if cfg.CatalogerConfig.Relationships.FileOwnershipOverlap {
		addFileOwnershipOverlapRelationships(builder.(task.SBOMAccessor))
	}

	// apply exclusions to the package catalog
	// default config value for this is true
	// https://github.com/anchore/syft/issues/931
	if cfg.CatalogerConfig.Relationships.ExcludeBinaryPackagesWithFileOwnershipOverlap {
		for _, r := range s.Relationships {
			if pkg.ExcludeBinaryByFileOwnershipOverlap(r, s.Artifacts.Packages) {
				s.Artifacts.Packages.Delete(r.To.ID())
				s.Relationships = removeRelationshipsByID(s.Relationships, r.To.ID())
			}
		}
	}

	// no need to consider source relationships for os -> binary exclusions
	s.Relationships = append(s.Relationships, newSourceRelationshipsFromCatalog(src, s.Artifacts.Packages)...)

	return &s, nil
}

func monitorPackageCatalogingTask() *monitor.CatalogerTask {
	info := monitor.GenericTask{
		Title: monitor.Title{
			Default: "Packages",
		},
		ID:            monitor.PackageCatalogingTaskID,
		HideOnSuccess: false,
		ParentID:      monitor.TopLevelCatalogingTaskID,
	}

	return monitor.StartCatalogerTask(info, -1, "")
}

func monitorCatalogingTask(srcID artifact.ID, tasks [][]task.Task) *monitor.CatalogerTask {
	info := monitor.GenericTask{
		Title: monitor.Title{
			Default:      "Catalog contents",
			WhileRunning: "Cataloging contents",
			OnSuccess:    "Cataloged contents",
		},
		ID:            monitor.TopLevelCatalogingTaskID,
		Context:       string(srcID),
		HideOnSuccess: false,
	}

	var length int64
	for _, tg := range tasks {
		length += int64(len(tg))
	}

	return monitor.StartCatalogerTask(info, length, "")
}

func removeRelationshipsByID(relationships []artifact.Relationship, id artifact.ID) []artifact.Relationship {
	var filtered []artifact.Relationship
	for _, r := range relationships {
		if r.To.ID() != id && r.From.ID() != id {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func newSourceRelationshipsFromCatalog(src source.Source, c *pkg.Collection) []artifact.Relationship {
	relationships := make([]artifact.Relationship, 0) // Should we pre-allocate this by giving catalog a Len() method?
	for p := range c.Enumerate() {
		relationships = append(relationships, artifact.Relationship{
			From: src,
			To:   p,
			Type: artifact.ContainsRelationship,
		})
	}

	return relationships
}

func addFileOwnershipOverlapRelationships(accessor task.SBOMAccessor) {
	var relationships []artifact.Relationship

	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		relationships = pkg.RelationshipsByFileOwnership(s.Artifacts.Packages)
	})

	accessor.WriteToSBOM(func(s *sbom.SBOM) {
		s.Relationships = append(s.Relationships, relationships...)
	})
}

func formatTaskNames(tasks []task.Task) []string {
	set := strset.New()
	for _, td := range tasks {
		set.Add(td.Name())
	}
	list := set.List()
	sort.Strings(list)
	return list
}
