package syft

import (
	"fmt"
	"sort"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/scylladb/go-set/strset"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/internal/task"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// nolint:funlen
func CreateSBOM(src source.Source, cfg *CreateSBOMConfig) (*sbom.SBOM, error) {
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
			Configuration: configurationAuditTrail{
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
