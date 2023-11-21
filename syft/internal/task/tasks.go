package task

import (
	"fmt"
)

type tasks []Task

// Select the set of tasks to run based on the given expression(s).
func (tds tasks) Select(nodes ...expressionNode) (tasks, error) {
	if len(nodes) == 0 {
		return tds, nil
	}

	s := newSet()
	for _, node := range nodes {
		selection := tds.selectTasksWithAllTags(node.Requirements...)

		switch node.Prefix {
		case "+", "":
			s.Add(selection...)
		case "-":
			s.Remove(selection...)
		case "&":
			s.Intersect(selection...)
		default:
			return nil, fmt.Errorf("invalid node prefix: %q", node.Prefix)
		}
	}
	return s.Tasks(), nil
}

func (tds tasks) selectTasksWithAllTags(tags ...string) tasks {
	var result []Task
	for _, td := range tds {
		if ts, ok := td.(Selector); ok {
			// use the selector to verify all tags
			if ts.HasAllSelectors(tags...) {
				result = append(result, td)
			}
		} else if len(tags) == 1 {
			// only do exact name matching
			if td.Name() == tags[0] {
				result = append(result, td)
			}
		}
	}
	return result
}
