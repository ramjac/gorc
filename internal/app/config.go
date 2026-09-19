package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-viper/mapstructure/v2"
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
	if err := v.Unmarshal(&cfg, func(dc *mapstructure.DecoderConfig) {
		dc.TagName = "mapstructure"
	}); err != nil {
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

	settings := v.AllSettings()
	vars := make(map[string]string, len(settings))
	for key, value := range settings {
		text, err := stringifyConfigValue(value)
		if err != nil {
			return nil, "", fmt.Errorf("vars file value %q: %w", key, err)
		}
		vars[key] = text
	}
	return vars, abs, nil
}

func stringifyConfigValue(value any) (string, error) {
	switch typed := value.(type) {
	case nil:
		return "", nil
	case string:
		return typed, nil
	case bool:
		if typed {
			return "true", nil
		}
		return "false", nil
	case int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64:
		return fmt.Sprint(typed), nil
	default:
		data, err := json.Marshal(typed)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
}

func parseTimeout(value string) (time.Duration, error) {
	if value == "" {
		return 0, nil
	}
	return time.ParseDuration(value)
}
