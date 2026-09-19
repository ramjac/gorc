package app

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

func loadConfig(path string) (Config, string, error) {
	for _, candidate := range configCandidates(path) {
		cfg, abs, found, err := readConfig(candidate, path == "")
		if err != nil {
			return Config{}, "", err
		}
		if found {
			return cfg, abs, nil
		}
	}
	return Config{Vars: map[string]string{}}, "", nil
}

func configCandidates(path string) []string {
	paths := []string{}
	if path != "" {
		return append(paths, path)
	}
	if env := os.Getenv("GORC_CONFIG"); env != "" {
		paths = append(paths, env)
	}
	paths = append(paths, ".gorc.json", "gorc.json")
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".config", "gorc", "config.json"))
	}
	return paths
}

func readConfig(path string, allowMissing bool) (Config, string, bool, error) {
	if path == "" {
		return Config{}, "", false, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return Config{}, "", false, err
	}
	if allowMissing {
		if _, err := os.Stat(abs); errors.Is(err, os.ErrNotExist) {
			return Config{}, "", false, nil
		} else if err != nil {
			return Config{}, "", false, err
		}
	}

	v := viper.New()
	v.SetConfigFile(abs)
	if err := v.ReadInConfig(); err != nil {
		if allowMissing {
			var notFound viper.ConfigFileNotFoundError
			if errors.As(err, &notFound) || errors.Is(err, os.ErrNotExist) {
				return Config{}, "", false, nil
			}
		}
		return Config{}, "", false, err
	}

	cfg := Config{}
	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, "", false, err
	}
	if cfg.Vars == nil {
		cfg.Vars = map[string]string{}
	}
	return cfg, abs, true, nil
}

func loadVarsFile(path string) (map[string]string, string, error) {
	if path == "" {
		return map[string]string{}, "", nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, "", err
	}

	v := viper.New()
	v.SetConfigFile(abs)
	if err := v.ReadInConfig(); err != nil {
		return nil, "", err
	}

	vars := map[string]string{}
	if err := v.Unmarshal(&vars); err != nil {
		return nil, "", err
	}
	return vars, abs, nil
}

func parseTimeout(value string) (time.Duration, error) {
	if value == "" {
		return 0, nil
	}
	return time.ParseDuration(value)
}
