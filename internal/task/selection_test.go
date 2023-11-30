package task

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseExpressionsWithBasis(t *testing.T) {
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
		{
			name:  "respect prefix boundaries",
			basis: "image",
			expressions: []string{
				"os&installed",
				"-rpm,java",
				"javascript", // implicitly added to the replacement basis set
			},
			want: []expressionNode{
				{
					Requirements: []string{"os", "installed"},
				},
				{
					Requirements: []string{"javascript"},
				},
				{
					Prefix:       "-",
					Requirements: []string{"rpm"},
				},
				{
					Prefix:       "-",
					Requirements: []string{"java"},
				},
			},
		},
		{
			name:  "override basis with last node",
			basis: "image",
			// this input expression is valid but really makes no sense from a user perspective
			expressions: []string{
				"+os&installed", // does not replace basis, but adds to it
				"-rpm,java",
				"javascript", // implicitly replaces the basis
				"python",     // add to the basis
			},
			want: []expressionNode{
				{
					Requirements: []string{"javascript"},
				},
				{
					Requirements: []string{"python"},
				},
				{
					Requirements: []string{"os", "installed"},
				},
				{
					Prefix:       "-",
					Requirements: []string{"rpm"},
				},
				{
					Prefix:       "-",
					Requirements: []string{"java"},
				},
			},
		},
		{
			name:  "basis with multiple additional intersections",
			basis: "image",
			expressions: []string{
				"&javascript,package",
			},
			want: []expressionNode{
				{
					Requirements: []string{"image", "javascript", "package"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			got, err := parseExpressionsWithBasis(tt.basis, tt.expressions...)
			tt.wantErr(t, err)
			if err != nil {
				return
			}

			if d := cmp.Diff(tt.want, got); d != "" {
				t.Errorf("parseExpressionsWithBasis() mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func Test_parseExpressionsWithBasis_Strings(t *testing.T) {
	tests := []struct {
		name  string
		basis string
		input string
		want  []string
	}{
		{
			name:  "empty",
			basis: "",
			input: "",
			want:  nil,
		},
		{
			name:  "single node",
			basis: "image",
			input: "",
			want:  []string{"image"},
		},
		{
			name:  "multiple nodes",
			basis: "image",
			input: "-rpm",
			want: []string{
				"image",
				"-rpm",
			},
		},
		{
			name:  "prefix is simplified",
			basis: "image",
			input: "+rpm,-java,+os&installed",
			want: []string{
				"image",
				"rpm",
				"os&installed",
				"-java",
			},
		},
		{
			name:  "prefix joins with basis",
			basis: "image",
			input: "&java",
			want:  []string{"image&java"},
		},
		{
			name:  "prefix joins with all nodes",
			basis: "image",
			input: "&java,&javascript",
			want: []string{
				"image&java&javascript",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodes, err := parseExpressionsWithBasis(tt.basis, tt.input)
			require.NoError(t, err)
			assert.Equalf(t, tt.want, expressionNodes(nodes).Strings(), "Strings()")
		})
	}
}

func TestParseExpression(t *testing.T) {
	tests := []struct {
		name                                   string
		input                                  string
		wantBasis, wantAdditions, wantRemovals []expressionNode
		wantErr                                require.ErrorAssertionFunc
	}{
		{
			name:  "removals interleaved with basis",
			input: "image,os&installed,-rpm,java,javascript",
			wantBasis: []expressionNode{
				{Prefix: "", Requirements: []string{"image"}},
				{Prefix: "", Requirements: []string{"os", "installed"}},
			},
			wantRemovals: []expressionNode{
				{Prefix: "-", Requirements: []string{"rpm"}},
				{Prefix: "-", Requirements: []string{"java"}},
				{Prefix: "-", Requirements: []string{"javascript"}},
			},
		},
		{
			name:      "additions interleaved with additions",
			input:     "+os&installed,-rpm,java,+javascript,python",
			wantBasis: nil,
			wantAdditions: []expressionNode{
				{Prefix: "+", Requirements: []string{"os", "installed"}},
				{Prefix: "+", Requirements: []string{"javascript"}},
				{Prefix: "+", Requirements: []string{"python"}},
			},
			wantRemovals: []expressionNode{
				{Prefix: "-", Requirements: []string{"rpm"}},
				{Prefix: "-", Requirements: []string{"java"}},
			},
		},
		{
			name:  "basis with additions and removals",
			input: "java,python,go,-installed,+sbom",
			wantBasis: []expressionNode{
				{Prefix: "", Requirements: []string{"java"}},
				{Prefix: "", Requirements: []string{"python"}},
				{Prefix: "", Requirements: []string{"go"}},
			},
			wantAdditions: []expressionNode{
				{Prefix: "+", Requirements: []string{"sbom"}},
			},
			wantRemovals: []expressionNode{
				{Prefix: "-", Requirements: []string{"installed"}},
			},
		},
		{
			name:  "intersection with additions and removals",
			input: "&java,python,go,-installed,+sbom",
			wantBasis: []expressionNode{
				{Prefix: "&", Requirements: []string{"java", "python", "go"}},
			},
			wantAdditions: []expressionNode{
				{Prefix: "+", Requirements: []string{"sbom"}},
			},
			wantRemovals: []expressionNode{
				{Prefix: "-", Requirements: []string{"installed"}},
			},
		},
		{
			name:  "basis with intersections",
			input: "image,&java,python,go,-installed,+sbom",
			wantBasis: []expressionNode{
				{Prefix: "", Requirements: []string{"image", "java", "python", "go"}},
			},
			wantAdditions: []expressionNode{
				{Prefix: "+", Requirements: []string{"sbom"}},
			},
			wantRemovals: []expressionNode{
				{Prefix: "-", Requirements: []string{"installed"}},
			},
		},
		{
			name:    "invalid node",
			input:   "image,~installed",
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			gotBasis, gotAdditions, gotRemovals, err := parseExpression(tt.input)
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			if d := cmp.Diff(tt.wantBasis, gotBasis); d != "" {
				t.Errorf("parseExpression() mismatch in basis (-want +got):\n%s", d)
			}
			if d := cmp.Diff(tt.wantAdditions, gotAdditions); d != "" {
				t.Errorf("parseExpression() mismatch in additions (-want +got):\n%s", d)
			}
			if d := cmp.Diff(tt.wantRemovals, gotRemovals); d != "" {
				t.Errorf("parseExpression() mismatch in removals (-want +got):\n%s", d)
			}
		})
	}
}

func Test_parseExpressions(t *testing.T) {
	tests := []struct {
		name        string
		expressions []string
		want        []expressionNode
		wantErr     require.ErrorAssertionFunc
	}{
		{
			name:        "empty",
			expressions: nil,
			want:        nil,
		},
		{
			name:        "effectively empty",
			expressions: []string{","},
			want:        nil,
		},
		{
			name:        "ignore empty nodes",
			expressions: []string{",a,,,"},
			want: []expressionNode{
				{
					Requirements: []string{"a"},
				},
			},
		},
		{
			name:        "single comma-delimited expression",
			expressions: []string{"a,b"},
			want: []expressionNode{
				{
					Requirements: []string{"a"},
				},
				{
					Requirements: []string{"b"},
				},
			},
		},
		{
			name:        "group prefix",
			expressions: []string{"+a,b"},
			want: []expressionNode{
				{
					Prefix:       "+",
					Requirements: []string{"a"},
				},
				{
					Prefix:       "+",
					Requirements: []string{"b"},
				},
			},
		},
		{
			name:        "ignore spaces",
			expressions: []string{"  +  a  ,  b  "},
			want: []expressionNode{
				{
					Prefix:       "+",
					Requirements: []string{"a"},
				},
				{
					Prefix:       "+",
					Requirements: []string{"b"},
				},
			},
		},
		{
			name:        "multiple group prefixes",
			expressions: []string{"+a,b,+c"},
			want: []expressionNode{
				{
					Prefix:       "+",
					Requirements: []string{"a"},
				},
				{
					Prefix:       "+",
					Requirements: []string{"b"},
				},
				{
					Prefix:       "+",
					Requirements: []string{"c"},
				},
			},
		},
		{
			name:        "multiple conflicting group prefixes",
			expressions: []string{"+a,b,-c,d"},
			want: []expressionNode{
				{
					Prefix:       "+",
					Requirements: []string{"a"},
				},
				{
					Prefix:       "+",
					Requirements: []string{"b"},
				},
				{
					Prefix:       "-",
					Requirements: []string{"c"},
				},
				{
					Prefix:       "-",
					Requirements: []string{"d"},
				},
			},
		},
		{
			name:        "remove unnecessary prefixes",
			expressions: []string{"first,second,+a,b,-c,d"},
			want: []expressionNode{
				{
					Requirements: []string{"first"},
				},
				{
					Requirements: []string{"second"},
				},
				{
					Requirements: []string{"a"},
				},
				{
					Requirements: []string{"b"},
				},
				{
					Prefix:       "-",
					Requirements: []string{"c"},
				},
				{
					Prefix:       "-",
					Requirements: []string{"d"},
				},
			},
		},
		{
			name:        "only prefixes (invalid)",
			expressions: []string{"+-+"},
			wantErr:     require.Error,
		},
		{
			name:        "multiple prefixes on a node (invalid)",
			expressions: []string{"+-+&a"},
			wantErr:     require.Error,
		},
		{
			name:        "bad prefix (invalid)",
			expressions: []string{"~a"},
			wantErr:     require.Error,
		},
		{
			name:        "bad node characters (invalid)",
			expressions: []string{"a~'something"},
			wantErr:     require.Error,
		},
		{
			name:        "intersect prefix",
			expressions: []string{"&a"},
			want: []expressionNode{
				{
					Prefix:       "&",
					Requirements: []string{"a"},
				},
			},
		},
		{
			name:        "error on extra prefixes",
			expressions: []string{"++a"},
			wantErr:     require.Error,
		},
		{
			name:        "names with hyphens",
			expressions: []string{"+sbom-cataloger,rust&installed,-python-installed-package-cataloger,go-module-binary-cataloger"},
			want: []expressionNode{
				{
					Prefix:       "+",
					Requirements: []string{"sbom-cataloger"},
				},
				{
					Prefix:       "+",
					Requirements: []string{"rust", "installed"},
				},
				{
					Prefix:       "-",
					Requirements: []string{"python-installed-package-cataloger"},
				},
				{
					Prefix:       "-",
					Requirements: []string{"go-module-binary-cataloger"},
				},
			},
		},
		{
			name:        "sort group prefixes",
			expressions: []string{"-c,d,+a,b"},
			want: []expressionNode{
				{
					Prefix:       "+",
					Requirements: []string{"a"},
				},
				{
					Prefix:       "+",
					Requirements: []string{"b"},
				},
				{
					Prefix:       "-",
					Requirements: []string{"c"},
				},
				{
					Prefix:       "-",
					Requirements: []string{"d"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			got, err := parseExpressions(tt.expressions)
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
