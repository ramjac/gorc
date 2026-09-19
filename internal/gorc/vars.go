package gorc

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

var variablePattern = regexp.MustCompile(`\{\{\s*([^{}]+?)\s*\}\}`)

type resolver struct {
	RequestVars map[string]string
	FileVars    map[string]string
	ConfigVars  map[string]string
	CLIVars     map[string]string
}

func resolveString(input string, vars resolver) (string, error) {
	previous := input
	for i := 0; i < 10; i++ {
		replaced := variablePattern.ReplaceAllStringFunc(previous, func(match string) string {
			key := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(match, "{{"), "}}"))
			value, ok := resolveVariable(key, vars)
			if !ok {
				return match
			}
			return value
		})
		if replaced == previous {
			if strings.Contains(replaced, "{{") {
				return replaced, nil
			}
			return replaced, nil
		}
		previous = replaced
	}
	return previous, fmt.Errorf("variable expansion exceeded recursion limit")
}

func resolveVariable(key string, vars resolver) (string, bool) {
	fields := strings.Fields(key)
	if len(fields) == 2 {
		switch fields[0] {
		case "$env":
			return os.LookupEnv(fields[1])
		case "$cli":
			value, ok := vars.CLIVars[fields[1]]
			return value, ok
		case "$config":
			value, ok := vars.ConfigVars[fields[1]]
			return value, ok
		case "$file":
			value, ok := vars.FileVars[fields[1]]
			return value, ok
		case "$request":
			value, ok := vars.RequestVars[fields[1]]
			return value, ok
		}
	}

	if value, ok := vars.CLIVars[key]; ok {
		return value, true
	}
	if value, ok := vars.RequestVars[key]; ok {
		return value, true
	}
	if value, ok := vars.FileVars[key]; ok {
		return value, true
	}
	if value, ok := vars.ConfigVars[key]; ok {
		return value, true
	}
	if value, ok := os.LookupEnv(key); ok {
		return value, true
	}
	if value, ok := os.LookupEnv(strings.ToUpper(strings.ReplaceAll(key, "-", "_"))); ok {
		return value, true
	}
	return "", false
}
