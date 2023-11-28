package cataloging

type Config struct {
	Search         SearchConfig         `yaml:"search" json:"search" mapstructure:"search"`
	Relationships  RelationshipsConfig  `yaml:"relationships" json:"relationships" mapstructure:"relationships"`
	DataGeneration DataGenerationConfig `yaml:"data-generation" json:"data-generation" mapstructure:"data-generation"`
}

func DefaultConfig() Config {
	return Config{
		Search:         DefaultSearchConfig(),
		Relationships:  DefaultRelationshipsConfig(),
		DataGeneration: DefaultDataGenerationConfig(),
	}
}

func (c Config) WithSearchConfig(searchConfig SearchConfig) Config {
	c.Search = searchConfig
	return c
}

func (c Config) WithRelationshipsConfig(relationshipsConfig RelationshipsConfig) Config {
	c.Relationships = relationshipsConfig
	return c
}

func (c Config) WithDataGenerationConfig(dataGenerationConfig DataGenerationConfig) Config {
	c.DataGeneration = dataGenerationConfig
	return c
}
