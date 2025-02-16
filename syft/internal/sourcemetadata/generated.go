// DO NOT EDIT: generated by syft/internal/sourcemetadata/generate/main.go

package sourcemetadata

import "github.com/gsoc2/syft/syft/source"

// AllTypes returns a list of all source metadata types that syft supports (that are represented in the source.Description.Metadata field).
func AllTypes() []any {
	return []any{source.DirectorySourceMetadata{}, source.FileSourceMetadata{}, source.StereoscopeImageSourceMetadata{}}
}
