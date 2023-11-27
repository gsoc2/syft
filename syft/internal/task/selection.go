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
	nodes, err := parseExpressionsWithBasis(basis, expressions...)
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

func parseExpressionsWithBasis(basis string, expressions ...string) ([]expressionNode, error) {
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
	var basis, additions, remove []expressionNode

	for idx, exp := range expressions {
		b, a, r, err := parseExpression(exp)
		if err != nil {
			return nil, fmt.Errorf("unable to parse expression %d (%q): %w", idx, exp, err)
		}

		basis = append(basis, b...)
		additions = append(additions, a...)
		remove = append(remove, r...)
	}

	if len(basis) > 0 {
		// treat all additions as if they were a basis (remove any + prefixes)
		for idx := range additions {
			additions[idx].Prefix = ""
		}
	}

	var all []expressionNode

	all = append(all, basis...)
	all = append(all, additions...)
	all = append(all, remove...)

	return all, nil
}

// parseExpression takes a singular expression and returns the set of basis nodes, additional nodes, and nodes to remove.
// Once a prefix is found then that prefix is inherited by all subsequent nodes until a new prefix is found. This implies
// that basis nodes must be first and have no prefix. No simplifications are performed at this point in processing,
// only creating nodes from string expressions.
func parseExpression(expression string) (basis, additions, removals []expressionNode, err error) {
	expression = strings.ReplaceAll(expression, " ", "")
	if expression == "" {
		return nil, nil, nil, nil
	}

	prefix := ""
	for _, segment := range strings.Split(expression, ",") {
		if segment == "" {
			continue
		}

		ogSegment := segment

		if hasOperatorPrefix(segment) {
			prefix = string(segment[0])
			segment = segment[1:]
		}

		if prefix == "&" {
			if len(basis) > 0 {
				// amend the last node in the basis with the new requirement
				basis[len(basis)-1].Requirements = append(basis[len(basis)-1].Requirements, segment)
				continue
			}
		}

		if !isValidNode(segment) {
			return nil, nil, nil, fmt.Errorf("invalid expression node: %q", ogSegment)
		}

		requirements := strings.Split(segment, "&")
		node := expressionNode{
			Prefix:       prefix,
			Requirements: requirements,
		}

		switch prefix {
		case "+":
			additions = append(additions, node)
		case "-":
			removals = append(removals, node)
		default:
			basis = append(basis, node)
		}
	}

	return basis, additions, removals, nil
}

func hasOperatorPrefix(s string) bool {
	return strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "&")
}

func (e expressionNodes) Strings() []string {
	var parts []string
	for _, node := range e {
		val := strings.ReplaceAll(node.String(), "+", "")
		if val != "" {
			parts = append(parts, val)
		}
	}

	return parts
}

func (e expressionNode) String() string {
	return e.Prefix + strings.Join(e.Requirements, "&")
}

func isValidNode(s string) bool {
	return expressionNodePattern.Match([]byte(s))
}
