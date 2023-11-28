package syft

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/pkg/cataloger/kernel"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
	"github.com/anchore/syft/syft/source"
)

func Test_configurationAuditTrail_MarshalJSON(t *testing.T) {

	tests := []struct {
		name string
		cfg  configurationAuditTrail
		want string
	}{
		{
			name: "gocase",
			cfg: configurationAuditTrail{
				CatalogerConfig: cataloging.Config{
					Search: cataloging.SearchConfig{
						Scope: source.SquashedScope,
					},
					Relationships:  cataloging.RelationshipsConfig{},
					DataGeneration: cataloging.DataGenerationConfig{},
				},
				PackagesConfig: pkgcataloging.Config{
					Golang:      golang.CatalogerConfig{},
					LinuxKernel: kernel.LinuxKernelCatalogerConfig{},
					Python:      python.CatalogerConfig{},
					Java:        java.CatalogerConfig{},
				},
				FilesConfig: filecataloging.Config{
					Selection: file.OwnedFilesSelection,
					Hashers: []crypto.Hash{
						crypto.SHA256,
					},
				},
				Catalogers: catalogerManifest{
					Requested:      []string{"requested"},
					CatalogersUsed: []string{"used"},
				},
				ExtraConfigs: nil,
			},
			// this is what is encoded as the expected result. Note that the order of the keys is sorted (which is not the case in structs)
			//{
			//  "catalog": {
			//    "data-generation": {
			//      "generate-cpes": false,
			//      "guess-language-from-purl": false
			//    },
			//    "relationships": {
			//      "exclude-binary-packages-with-file-ownership-overlap": false,
			//      "file-ownership": false,
			//      "file-ownership-overlap": false
			//    },
			//    "search": {
			//      "scope": "squashed"
			//    }
			//  },
			//  "catalogers": {
			//    "requested": [
			//      "requested"
			//    ],
			//    "used": [
			//      "used"
			//    ]
			//  },
			//  "files": {
			//    "hashers": [
			//      "sha-256"
			//    ],
			//    "selection": "owned-files"
			//  },
			//  "packages": {
			//    "golang": {
			//      "local-mod-cache-dir": "",
			//      "search-local-mod-cache-licenses": false,
			//      "search-remote-licenses": false
			//    },
			//    "java": {
			//      "include-indexed-archives": false,
			//      "include-unindexed-archives": false,
			//      "maven-base-url": "",
			//      "max-parent-recursive-depth": 0,
			//      "use-network": false
			//    },
			//    "linux-kernel": {
			//      "catalog-modules": false
			//    },
			//    "python": {
			//      "guess-unpinned-requirements": false
			//    }
			//  }
			//}
			want: `{"catalog":{"data-generation":{"generate-cpes":false,"guess-language-from-purl":false},"relationships":{"exclude-binary-packages-with-file-ownership-overlap":false,"file-ownership":false,"file-ownership-overlap":false},"search":{"scope":"squashed"}},"catalogers":{"requested":["requested"],"used":["used"]},"files":{"hashers":["sha-256"],"selection":"owned-files"},"packages":{"golang":{"local-mod-cache-dir":"","search-local-mod-cache-licenses":false,"search-remote-licenses":false},"java":{"include-indexed-archives":false,"include-unindexed-archives":false,"maven-base-url":"","max-parent-recursive-depth":0,"use-network":false},"linux-kernel":{"catalog-modules":false},"python":{"guess-unpinned-requirements":false}}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			got, err := tt.cfg.MarshalJSON()
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}
