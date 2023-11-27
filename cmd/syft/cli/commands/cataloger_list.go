package commands

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
)

type catalogerListOptions struct {
	Output     string   `yaml:"output" json:"output" mapstructure:"output"`
	Catalogers []string `yaml:"catalogers" json:"catalogers" mapstructure:"catalogers"`
}

func (o *catalogerListOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Output, "output", "o", "format to output the cataloger list (available: table, json)")

	flags.StringArrayVarP(&o.Catalogers, "select", "s", "select catalogers with an expression")
}

func CatalogerList(app clio.Application) *cobra.Command {
	opts := &catalogerListOptions{}

	return app.SetupCommand(&cobra.Command{
		Use:   "list [OPTIONS]",
		Short: "List available catalogers",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCatalogerList(opts)
		},
	}, opts)
}

func runCatalogerList(opts *catalogerListOptions) error {
	factories := task.DefaultPackageTaskFactories()
	tasks, err := factories.Tasks(cataloging.DefaultConfig(), pkgcataloging.DefaultConfig())
	if err != nil {
		return fmt.Errorf("unable to create cataloger tasks: %w", err)
	}

	if len(opts.Catalogers) > 0 {
		tasks, _, err = task.Select(tasks, "", opts.Catalogers...)
		if err != nil {
			return fmt.Errorf("unable to select catalogers: %w", err)
		}
	}

	var report string

	switch opts.Output {
	case "json":
		report, err = renderCatalogerListJSON(tasks, opts.Catalogers)
	case "table", "":
		report = renderCatalogerListTable(tasks, opts.Catalogers)
	}

	if err != nil {
		return fmt.Errorf("unable to render cataloger list: %w", err)
	}

	bus.Report(report)

	return nil
}

func renderCatalogerListJSON(tasks []task.Task, expressions []string) (string, error) {
	type node struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}

	names, tagsByName := extractTaskInfo(tasks)

	nodesByName := make(map[string]node)

	for name, tags := range tagsByName {
		if tags == nil {
			// ensure collections are not null
			tags = []string{}
		}
		nodesByName[name] = node{
			Name: name,
			Tags: tags,
		}
	}

	type document struct {
		Expressions []string `json:"expressions"`
		Catalogers  []node   `json:"catalogers"`
	}

	if expressions == nil {
		// ensure collections are not null
		expressions = []string{}
	}

	doc := document{
		Expressions: expressions,
	}

	for _, name := range names {
		doc.Catalogers = append(doc.Catalogers, nodesByName[name])
	}

	by, err := json.Marshal(doc)

	return string(by), err
}

func renderCatalogerListTable(tasks []task.Task, expressions []string) string {
	t := table.NewWriter()
	t.SetStyle(table.StyleLight)
	t.AppendHeader(table.Row{"Cataloger", "Tags"})

	names, tagsByName := extractTaskInfo(tasks)

	rowsByName := make(map[string]table.Row)

	for name, tags := range tagsByName {
		tagsStr := strings.Join(tags, ", ")
		rowsByName[name] = table.Row{name, tagsStr}
	}

	for _, name := range names {
		t.AppendRow(rowsByName[name])
	}

	report := t.Render()

	if len(expressions) > 0 {
		header := "Selected by expressions:\n"
		for _, expr := range expressions {
			header += fmt.Sprintf("  - %q\n", expr)
		}
		report = header + report
	}

	return report
}

func extractTaskInfo(tasks []task.Task) ([]string, map[string][]string) {
	tagsByName := make(map[string][]string)
	var names []string

	for _, tsk := range tasks {
		var tags []string
		name := tsk.Name()

		if s, ok := tsk.(task.Selector); ok {
			set := strset.New(s.Selectors()...)
			set.Remove(name)
			tags = set.List()
			sort.Strings(tags)
		}

		tagsByName[name] = tags
		names = append(names, name)
	}

	sort.Strings(names)

	return names, tagsByName
}
