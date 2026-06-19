package config

import (
	"fmt"

	"github.com/caarlos0/env/v11"
)

type Config struct {
	DatabaseURL string `env:"DATABASE_URL,required"`
	Port string `env:"PORT" envDefault:"8080"`
	BaseURL string `env:"BASE_URL" envDefault:"http://localhost:8080"`
	SecretKey string `env:"SECRET_KEY,required"`
}

func Load() (*Config, error) {
	cfg := &Config{}

	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("invalid env config: %v", err)
	}

	return cfg, nil
}