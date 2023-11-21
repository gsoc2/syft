package task

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_createBasisExpression(t *testing.T) {
	tests := []struct {
		name        string
		basis       string
		expressions []string
		want        []expressionNode
		wantErr     require.ErrorAssertionFunc
	}{
		{
			name:        "no expressions should use the basis",
			basis:       "image",
			expressions: []string{},
			want: []expressionNode{
				{
					Requirements: []string{"image"},
				},
			},
		},
		{
			name:  "relative - prefix should use the basis",
			basis: "image",
			expressions: []string{
				"-rpm",
			},
			want: []expressionNode{
				{
					Requirements: []string{"image"},
				},
				{
					Prefix:       "-",
					Requirements: []string{"rpm"},
				},
			},
		},
		{
			name:  "relative & prefix should use the basis",
			basis: "image",
			expressions: []string{
				"&rpm",
			},
			want: []expressionNode{
				{
					Requirements: []string{"image", "rpm"},
				},
			},
		},
		{
			name:  "override the basis",
			basis: "image",
			expressions: []string{
				"os&installed",
				"-rpm",
			},
			want: []expressionNode{
				{
					Requirements: []string{"os", "installed"},
				},
				{
					Prefix:       "-",
					Requirements: []string{"rpm"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			got, err := createExpressionWithBasis(tt.basis, tt.expressions...)
			tt.wantErr(t, err)
			if err != nil {
				return
			}

			if d := cmp.Diff(tt.want, got); d != "" {
				t.Errorf("createExpressionWithBasis() mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func Test_createExpressionWithBasis_to_expressionNodes_String(t *testing.T) {
	tests := []struct {
		name  string
		basis string
		input string
		want  string
	}{
		{
			name:  "empty",
			basis: "",
			input: "",
			want:  "",
		},
		{
			name:  "single node",
			basis: "image",
			input: "",
			want:  "image",
		},
		{
			name:  "multiple nodes",
			basis: "image",
			input: "-rpm",
			want:  "image,-rpm",
		},
		{
			name:  "prefix is simplified",
			basis: "image",
			input: "+rpm,-java,+os&installed",
			want:  "image,rpm,os&installed,-java",
		},
		{
			name:  "prefix joins with basis",
			basis: "image",
			input: "&java",
			want:  "image&java",
		},
		{
			name:  "prefix joins with all nodes",
			basis: "image",
			input: "&java,&javascript",
			want:  "image&java&javascript",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodes, err := createExpressionWithBasis(tt.basis, tt.input)
			require.NoError(t, err)
			assert.Equalf(t, tt.want, expressionNodes(nodes).String(), "String()")
		})
	}
}
