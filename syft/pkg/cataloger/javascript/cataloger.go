/*
Package javascript provides a concrete Cataloger implementation for packages relating to the JavaScript language ecosystem.
*/
package javascript

import (
	"github.com/gsoc2/syft/syft/pkg"
	"github.com/gsoc2/syft/syft/pkg/cataloger/generic"
)

// NewPackageCataloger returns a new cataloger object for NPM.
func NewPackageCataloger() pkg.Cataloger {
	return generic.NewCataloger("javascript-package-cataloger").
		WithParserByGlobs(parsePackageJSON, "**/package.json")
}

// NewLockCataloger returns a new cataloger object for NPM (and NPM-adjacent, such as yarn) lock files.
func NewLockCataloger() pkg.Cataloger {
	return generic.NewCataloger("javascript-lock-cataloger").
		WithParserByGlobs(parsePackageLock, "**/package-lock.json").
		WithParserByGlobs(parseYarnLock, "**/yarn.lock").
		WithParserByGlobs(parsePnpmLock, "**/pnpm-lock.yaml")
}
