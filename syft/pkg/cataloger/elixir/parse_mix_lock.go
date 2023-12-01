package elixir

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/gsoc2/syft/internal/log"
	"github.com/gsoc2/syft/syft/artifact"
	"github.com/gsoc2/syft/syft/file"
	"github.com/gsoc2/syft/syft/pkg"
	"github.com/gsoc2/syft/syft/pkg/cataloger/generic"
)

// integrity check
var _ generic.Parser = parseMixLock

var mixLockDelimiter = regexp.MustCompile(`[%{}\n" ,:]+`)

// parseMixLock parses a mix.lock and returns the discovered Elixir packages.
func parseMixLock(_ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	r := bufio.NewReader(reader)

	var packages []pkg.Package
	for {
		line, err := r.ReadString('\n')
		switch {
		case errors.Is(io.EOF, err):
			return packages, nil, nil
		case err != nil:
			return nil, nil, fmt.Errorf("failed to parse mix.lock file: %w", err)
		}
		tokens := mixLockDelimiter.Split(line, -1)
		if len(tokens) < 6 {
			continue
		}
		name, version, hash, hashExt := tokens[1], tokens[4], tokens[5], tokens[len(tokens)-2]

		if name == "" {
			log.WithFields("path", reader.RealPath).Debug("skipping empty package name from mix.lock file")
			continue
		}

		packages = append(packages,
			newPackage(
				pkg.ElixirMixLockEntry{
					Name:       name,
					Version:    version,
					PkgHash:    hash,
					PkgHashExt: hashExt,
				},
				reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
		)
	}
}
