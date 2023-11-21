package task

import (
	"fmt"
	"regexp"
	"strings"
)

var expressionNodePattern = regexp.MustCompile(`^([a-zA-Z0-9][a-zA-Z0-9-+]*&?)+$`)

type expressionNodes []expressionNode

type expressionNode struct {
	Prefix       string
	Requirements []string
}

func Select(allTasks []Task, basis string, expressions ...string) ([]Task, []string, error) {
	nodes, err := createExpressionWithBasis(basis, expressions...)
	if err != nil {
		return nil, nil, err
	}

	if len(nodes) > 0 {
		allTasks, err = tasks(allTasks).Select(nodes...)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to select package cataloger tasks: %w", err)
		}

		if len(allTasks) == 0 {
			return nil, nil, fmt.Errorf("no package cataloger tasks selected")
		}
	}

	return allTasks, expressionNodes(nodes).Strings(), nil
}

func createExpressionWithBasis(basis string, expressions ...string) ([]expressionNode, error) {
	nodes, err := parseExpressions(expressions)
	if err != nil {
		return nil, err
	}

	if len(nodes) > 0 && nodes[0].Prefix != "" || len(nodes) == 0 {
		if len(nodes) > 0 && nodes[0].Prefix == "&" {
			// augment the node requirements
			nodes[0].Requirements = append([]string{basis}, nodes[0].Requirements...)
		} else {
			// add a new node with the basis
			nodes = append([]expressionNode{
				{
					Prefix:       "",
					Requirements: []string{basis},
				},
			}, nodes...)
		}

		if nodes[0].Prefix == "&" {
			nodes[0].Prefix = ""
		}
	}

	return nodes, nil
}

func parseExpressions(expressions []string) ([]expressionNode, error) {
	expression := strings.Join(expressions, ",")
	expression = strings.ReplaceAll(strings.ToLower(expression), " ", "")
	fields := strings.Split(expression, ",")

	var remaining, remove []expressionNode

	var firstPrefix string
	var prefix string

	for idx, field := range fields {
		ogField := field

		if hasOperatorPrefix(field) {
			prefix = field[0:1]
			field = strings.TrimLeft(field, prefix)
		}

		if field != strings.TrimLeft(field, "+-&") {
			return nil, fmt.Errorf("invalid node expression: %q", ogField)
		}

		if idx == 0 {
			firstPrefix = prefix
		} else if prefix == "+" && firstPrefix == "" {
			prefix = ""
		}

		if len(field) == 0 {
			continue
		}

		if !isValidNode(field) {
			return nil, fmt.Errorf("invalid node expression: %q", ogField)
		}

		var requiredTags []string
		for _, s := range strings.Split(field, "&") {
			if s != "" {
				requiredTags = append(requiredTags, s)
			}
		}

		if prefix == "&" && len(remaining) > 0 {
			// conjoin with requirements of the last node. This specifically does NOT interact with set removals.
			lastRemaining := len(remaining) - 1
			remaining[lastRemaining].Requirements = append(remaining[lastRemaining].Requirements, requiredTags...)
			continue
		}

		node := expressionNode{
			Prefix:       prefix,
			Requirements: requiredTags,
		}

		if prefix == "-" {
			remove = append(remove, node)
			continue
		}
		remaining = append(remaining, node)
	}

	return append(remaining, remove...), nil
}

func hasOperatorPrefix(s string) bool {
	return strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "&")
}

func (e expressionNodes) String() string {
	return strings.Join(e.Strings(), ",")
}

func (e expressionNodes) Strings() []string {
	var parts []string
	for _, node := range e {
		parts = append(parts, strings.ReplaceAll(node.String(), "+", ""))
	}

	return parts
}

func (e expressionNode) String() string {
	return e.Prefix + strings.Join(e.Requirements, "&")
}

func isValidNode(s string) bool {
	return expressionNodePattern.Match([]byte(s))
}
