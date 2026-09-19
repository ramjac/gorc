package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

func loadConfig(path string) (Config, string, error) {
	paths := []string{}
	if path != "" {
		paths = append(paths, path)
	} else {
		if env := os.Getenv("GORC_CONFIG"); env != "" {
			paths = append(paths, env)
		}
		paths = append(paths, ".gorc.json", "gorc.json")
		if home, err := os.UserHomeDir(); err == nil {
			paths = append(paths, filepath.Join(home, ".config", "gorc", "config.json"))
		}
	}

	for _, candidate := range paths {
		if candidate == "" {
			continue
		}
		abs, err := filepath.Abs(candidate)
		if err != nil {
			return Config{}, "", err
		}
		data, err := os.ReadFile(abs)
		if errors.Is(err, os.ErrNotExist) && path == "" {
			continue
		}
		if err != nil {
			return Config{}, "", err
		}
		cfg := Config{}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return Config{}, "", err
		}
		if cfg.Vars == nil {
			cfg.Vars = map[string]string{}
		}
		return cfg, abs, nil
	}

	return Config{Vars: map[string]string{}}, "", nil
}

func loadVarsFile(path string) (map[string]string, string, error) {
	if path == "" {
		return map[string]string{}, "", nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, "", err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, "", err
	}
	vars := map[string]string{}
	if err := json.Unmarshal(data, &vars); err != nil {
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
