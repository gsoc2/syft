package task

import (
	"fmt"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/file"
)

var _ interface {
	Task
	Selector
} = (*task)(nil)

// Task is a function that can wrap a cataloger to populate the SBOM with data (coordinated through the mutex).
type Task interface {
	Name() string
	Execute(file.Resolver, SBOMBuilder) error
}

type Selector interface {
	HasAllSelectors(...string) bool
}

type task struct {
	name      string
	selectors *strset.Set
	task      func(file.Resolver, SBOMBuilder) error
}

func NewTask(name string, tsk func(file.Resolver, SBOMBuilder) error, tags ...string) Task {
	if tsk == nil {
		panic(fmt.Errorf("task cannot be nil"))
	}
	tags = append(tags, name)
	return &task{
		name:      name,
		selectors: strset.New(tags...),
		task:      tsk,
	}
}

func (t task) HasAllSelectors(ids ...string) bool {
	// tags or name
	return t.selectors.Has(ids...)
}

func (t task) Name() string {
	return t.name
}

func (t task) Execute(resolver file.Resolver, sbom SBOMBuilder) error {
	return t.task(resolver, sbom)
}
