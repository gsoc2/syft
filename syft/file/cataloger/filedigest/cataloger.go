package filedigest

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/dustin/go-humanize"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/gsoc2/syft/internal"
	"github.com/gsoc2/syft/internal/bus"
	intFile "github.com/gsoc2/syft/internal/file"
	"github.com/gsoc2/syft/internal/log"
	"github.com/gsoc2/syft/syft/event/monitor"
	"github.com/gsoc2/syft/syft/file"
	intCataloger "github.com/gsoc2/syft/syft/file/cataloger/internal"
)

var ErrUndigestableFile = errors.New("undigestable file")

type Cataloger struct {
	hashes []crypto.Hash
}

func NewCataloger(hashes []crypto.Hash) *Cataloger {
	return &Cataloger{
		hashes: hashes,
	}
}

func (i *Cataloger) Catalog(resolver file.Resolver, coordinates ...file.Coordinates) (map[file.Coordinates][]file.Digest, error) {
	results := make(map[file.Coordinates][]file.Digest)
	var locations []file.Location

	if len(coordinates) == 0 {
		locations = intCataloger.AllRegularFiles(resolver)
	} else {
		for _, c := range coordinates {
			locations = append(locations, file.NewLocationFromCoordinates(c))
		}
	}

	prog := digestsCatalogingProgress(int64(len(locations)))
	for _, location := range locations {
		prog.Increment()
		prog.AtomicStage.Set(location.Path())

		result, err := i.catalogLocation(resolver, location)

		if errors.Is(err, ErrUndigestableFile) {
			continue
		}

		if internal.IsErrPathPermission(err) {
			log.Debugf("file digests cataloger skipping %q: %+v", location.RealPath, err)
			continue
		}

		if err != nil {
			return nil, err
		}
		prog.Increment()
		results[location.Coordinates] = result
	}

	log.Debugf("file digests cataloger processed %d files", prog.Current())

	prog.AtomicStage.Set(fmt.Sprintf("%s digests", humanize.Comma(prog.Current())))
	prog.SetCompleted()

	return results, nil
}

func (i *Cataloger) catalogLocation(resolver file.Resolver, location file.Location) ([]file.Digest, error) {
	meta, err := resolver.FileMetadataByLocation(location)
	if err != nil {
		return nil, err
	}

	// we should only attempt to report digests for files that are regular files (don't attempt to resolve links)
	if meta.Type != stereoscopeFile.TypeRegular {
		return nil, ErrUndigestableFile
	}

	contentReader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(contentReader, location.AccessPath)

	digests, err := intFile.NewDigestsFromFile(contentReader, i.hashes)
	if err != nil {
		return nil, internal.ErrPath{Context: "digests-cataloger", Path: location.RealPath, Err: err}
	}

	return digests, nil
}

func digestsCatalogingProgress(locations int64) *monitor.CatalogerTaskProgress {
	info := monitor.GenericTask{
		Title: monitor.Title{
			Default:      "Catalog file digests",
			WhileRunning: "Cataloging file digests",
			OnSuccess:    "Cataloged file digests",
		},
	}

	return bus.StartCatalogerTask(info, locations, "")
}
