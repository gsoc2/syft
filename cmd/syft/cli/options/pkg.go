package options

type pkg struct {
	SearchUnindexedArchives         bool `yaml:"search-unindexed-archives" json:"search-unindexed-archives" mapstructure:"search-unindexed-archives"`
	SearchIndexedArchives           bool `yaml:"search-indexed-archives" json:"search-indexed-archives" mapstructure:"search-indexed-archives"`
	ExcludeBinaryOverlapByOwnership bool `yaml:"exclude-binary-overlap-by-ownership" json:"exclude-binary-overlap-by-ownership" mapstructure:"exclude-binary-overlap-by-ownership"` // exclude synthetic binary packages owned by os package files
}

func defaultPkg() pkg {
	return pkg{
		SearchIndexedArchives:           true,
		SearchUnindexedArchives:         false,
		ExcludeBinaryOverlapByOwnership: true,
	}
}
