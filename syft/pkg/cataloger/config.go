package cataloger

import (
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/pkg/cataloger/kernel"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
)

type Config struct {
	Golang      golang.CatalogerConfig            `yaml:"golang" json:"golang" mapstructure:"golang"`
	LinuxKernel kernel.LinuxKernelCatalogerConfig `yaml:"linux-kernel" json:"linux-kernel" mapstructure:"linux-kernel"`
	Python      python.CatalogerConfig            `yaml:"python" json:"python" mapstructure:"python"`
	Java        java.CatalogerConfig              `yaml:"java" json:"java" mapstructure:"java"`
}

func DefaultConfig() Config {
	return Config{
		Golang:      golang.DefaultCatalogerConfig(),
		LinuxKernel: kernel.DefaultLinuxCatalogerConfig(),
		Python:      python.DefaultCatalogerConfig(),
		Java:        java.DefaultCatalogerConfig(),
	}
}
