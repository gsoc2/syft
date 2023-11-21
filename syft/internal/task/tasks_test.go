package task

import (
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

func dummyTask(name string, tags ...string) Task {
	return NewTask(name, func(resolver file.Resolver, sbom SBOMBuilder) error {
		panic("not implemented")
	}, tags...)
}

// note: this test fixture does not need to be kept up to date here, but makes a great test subject
func createPackageTaskDescriptors() tasks {
	return []Task{
		// OS package installed catalogers
		dummyTask("alpm-db-cataloger", "directory", "installed", "image", "os", "alpm", "archlinux"),
		dummyTask("apk-db-cataloger", "directory", "installed", "image", "os", "apk", "alpine"),
		dummyTask("dpkg-db-cataloger", "directory", "installed", "image", "os", "dpkg", "debian"),
		dummyTask("portage-cataloger", "directory", "installed", "image", "os", "portage", "gentoo"),
		dummyTask("rpm-db-cataloger", "directory", "installed", "image", "os", "rpm", "redhat"),

		// OS package declared catalogers
		dummyTask("rpm-archive-cataloger", "declared", "directory", "os", "rpm", "redhat"),

		// language-specific package installed catalogers
		dummyTask("conan-info-cataloger", "installed", "image", "language", "cpp", "conan"),
		dummyTask("javascript-package-cataloger", "installed", "image", "language", "javascript", "node"),
		dummyTask("php-composer-installed-cataloger", "installed", "image", "language", "php", "composer"),
		dummyTask("ruby-installed-gemspec-cataloger", "installed", "image", "language", "ruby", "gem"),
		dummyTask("rust-cargo-lock-cataloger", "installed", "image", "language", "rust", "binary"),

		// language-specific package declared catalogers
		dummyTask("conan-cataloger", "declared", "directory", "language", "cpp", "conan"),
		dummyTask("dart-pubspec-lock-cataloger", "declared", "directory", "language", "dart"),
		dummyTask("dotnet-deps-cataloger", "declared", "directory", "language", "dotnet", "c#"),
		dummyTask("elixir-mix-lock-cataloger", "declared", "directory", "language", "elixir"),
		dummyTask("erlang-rebar-lock-cataloger", "declared", "directory", "language", "erlang"),

		// language-specific package for both image and directory scans (but not necessarily declared)
		dummyTask("dotnet-portable-executable-cataloger", "directory", "installed", "image", "language", "dotnet", "c#"),
		dummyTask("python-installed-package-cataloger", "directory", "installed", "image", "language", "python"),
		dummyTask("go-module-binary-cataloger", "directory", "installed", "image", "language", "go", "golang", "gomod", "binary"),
		dummyTask("java-archive-cataloger", "directory", "installed", "image", "language", "java", "maven"),
		dummyTask("graalvm-native-image-cataloger", "directory", "installed", "image", "language", "java"),

		// other package catalogers
		dummyTask("binary-cataloger", "declared", "directory", "image", "binary"),
		dummyTask("github-actions-usage-cataloger", "declared", "directory", "github", "github-actions"),
		dummyTask("github-action-workflow-usage-cataloger", "declared", "directory", "github", "github-actions"),
		dummyTask("sbom-cataloger", "declared", "directory", "image", "sbom"),
	}
}

func TestTaskDescriptors_Evaluate(t *testing.T) {
	tests := []struct {
		name        string
		tds         tasks
		expressions []string
		want        []string
	}{
		{
			name: "exact match",
			tds:  createPackageTaskDescriptors(),
			expressions: []string{
				"github-action-workflow-usage-cataloger",
			},
			want: []string{
				"github-action-workflow-usage-cataloger",
			},
		},
		{
			name: "tag match",
			tds:  createPackageTaskDescriptors(),
			expressions: []string{
				"java",
			},
			want: []string{
				"java-archive-cataloger",
				"graalvm-native-image-cataloger",
			},
		},
		{
			name: "intersection",
			tds:  createPackageTaskDescriptors(),
			expressions: []string{
				"directory&cpp",
			},
			want: []string{
				// note: the conan-info-cataloger is NOT selected too
				"conan-cataloger",
			},
		},
		{
			name: "prefix intersection",
			tds:  createPackageTaskDescriptors(),
			expressions: []string{
				"directory",
				"&cpp",
			},
			want: []string{
				// note: the conan-info-cataloger is NOT selected too
				"conan-cataloger",
			},
		},
		{
			name: "union",
			tds:  createPackageTaskDescriptors(),
			expressions: []string{
				"github,cpp",
			},
			want: []string{
				"github-actions-usage-cataloger",
				"github-action-workflow-usage-cataloger",
				"conan-cataloger",
				"conan-info-cataloger",
			},
		},
		{
			name: "empty intersection",
			tds:  createPackageTaskDescriptors(),
			expressions: []string{
				"github&cpp",
			},
			want: []string{},
		},
		{
			name: "subtract",
			tds:  createPackageTaskDescriptors(),
			expressions: []string{
				"cpp,-declared",
			},
			want: []string{
				"conan-info-cataloger",
			},
		},
		{
			name: "multiple overlapping subtractions",
			tds:  createPackageTaskDescriptors(),
			expressions: []string{
				"image,-declared,-cpp,-language",
			},
			want: []string{
				"dpkg-db-cataloger",
				"portage-cataloger",
				"rpm-db-cataloger",
				"alpm-db-cataloger",
				"apk-db-cataloger",
			},
		},
		{
			name: "multiple overlapping subtractions (different sections)",
			tds:  createPackageTaskDescriptors(),
			expressions: []string{
				"image",
				"-declared",
				"-cpp",
				"-language",
			},
			want: []string{
				"dpkg-db-cataloger",
				"portage-cataloger",
				"rpm-db-cataloger",
				"alpm-db-cataloger",
				"apk-db-cataloger",
			},
		},
		{
			name: "inherit sibling operation",
			tds:  createPackageTaskDescriptors(),
			expressions: []string{
				// gets arranged to "image,-declared,-cpp,-language"
				"image,-declared,cpp,language",
			},
			want: []string{
				"dpkg-db-cataloger",
				"portage-cataloger",
				"rpm-db-cataloger",
				"alpm-db-cataloger",
				"apk-db-cataloger",
			},
		},
		{
			name: "intersection as base set with subtraction",
			tds:  createPackageTaskDescriptors(),
			expressions: []string{
				"os&installed,-rpm",
			},
			want: []string{
				"dpkg-db-cataloger",
				"portage-cataloger",
				"alpm-db-cataloger",
				"apk-db-cataloger",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodes, err := parseExpressions(tt.expressions)
			require.NoError(t, err)
			got, err := tt.tds.Select(nodes...)
			require.NoError(t, err)
			gotNames := strset.New()
			for _, g := range got {
				gotNames.Add(g.Name())
			}
			list := gotNames.List()
			if !assert.ElementsMatch(t, list, tt.want) {
				t.Errorf("Evaluate() = %v, want %v", list, tt.want)
			}
		})
	}
}

func Test_simplifyExpressions(t *testing.T) {
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
			name:        "remove extra prefixes",
			expressions: []string{"++a"},
			want: []expressionNode{
				{
					Prefix:       "+",
					Requirements: []string{"a"},
				},
			},
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
