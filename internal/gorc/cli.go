package gorc

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(value string) error {
	*l = append(*l, value)
	return nil
}

func Run(args []string, stdout, stderr io.Writer) int {
	options, err := parseRunOptions(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := run(options, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func parseRunOptions(args []string) (RunOptions, error) {
	fs := flag.NewFlagSet("gorc", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		names       listFlag
		vars        listFlag
		indexes     string
		configPath  string
		varsFile    string
		outputFile  string
		bodyFile    string
		proxy       string
		httpVer     string
		insecure    bool
		all         bool
		interactive bool
	)
	fs.Var(&names, "name", "request name to execute")
	fs.Var(&vars, "var", "variable assignment key=value")
	fs.StringVar(&indexes, "index", "", "comma-separated request indexes (1-based)")
	fs.StringVar(&configPath, "config", "", "config file path")
	fs.StringVar(&varsFile, "vars-file", "", "JSON file containing variables")
	fs.StringVar(&outputFile, "output", "", "file to save the response body")
	fs.StringVar(&bodyFile, "body-file", "", "file to read the request body from")
	fs.StringVar(&proxy, "proxy", "", "proxy URL")
	fs.StringVar(&httpVer, "http-version", "", "HTTP version: auto, 1, 2, or 3")
	fs.BoolVar(&insecure, "insecure", false, "skip TLS verification")
	fs.BoolVar(&all, "all", false, "execute all requests in the .http file")
	fs.BoolVar(&interactive, "interactive", false, "interactively choose requests to execute")
	if err := fs.Parse(args); err != nil {
		return RunOptions{}, err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return RunOptions{}, errors.New("usage: gorc [flags] /absolute/or/relative/file.http")
	}

	indices, err := parseIndices(indexes)
	if err != nil {
		return RunOptions{}, err
	}
	parsedVars, err := parseVarAssignments(vars)
	if err != nil {
		return RunOptions{}, err
	}

	return RunOptions{
		FilePath:    rest[0],
		ConfigPath:  configPath,
		VarsFile:    varsFile,
		Vars:        parsedVars,
		Names:       names,
		Indices:     indices,
		All:         all,
		Interactive: interactive,
		BodyFile:    bodyFile,
		OutputFile:  outputFile,
		Proxy:       proxy,
		HTTPVersion: httpVer,
		Insecure:    insecure,
	}, nil
}

func run(options RunOptions, stdout, stderr io.Writer) error {
	httpFile, err := parseHTTPFile(options.FilePath)
	if err != nil {
		return err
	}
	if len(httpFile.Requests) == 0 {
		return errors.New("no requests found in file")
	}

	cfg, configPath, err := loadConfig(options.ConfigPath)
	if err != nil {
		return err
	}
	varsFile, varsPath, err := loadVarsFile(options.VarsFile)
	if err != nil {
		return err
	}
	for key, value := range varsFile {
		httpFile.FileVars[key] = value
	}

	timeout, err := parseTimeout(cfg.Timeout)
	if err != nil {
		return err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}

	runtime := RuntimeConfig{
		RootDir:     filepath.Dir(mustAbs(options.FilePath)),
		ConfigPath:  configPath,
		VarsFile:    varsPath,
		Config:      cfg,
		FileVars:    httpFile.FileVars,
		CLIVars:     options.Vars,
		CookieJar:   jar,
		Timeout:     timeout,
		OutputFile:  options.OutputFile,
		BodyFile:    options.BodyFile,
		Proxy:       options.Proxy,
		HTTPVersion: options.HTTPVersion,
		Insecure:    options.Insecure,
		Auth:        options.SelectedAuth,
	}

	selected, err := selectRequests(httpFile.Requests, options, stdout, stderr)
	if err != nil {
		return err
	}

	plans := make([]executionPlan, 0, len(selected))
	for _, request := range selected {
		plans = append(plans, executionPlan{
			Request: request,
			Runtime: runtime,
		})
	}
	return executeRequests(context.Background(), plans, stdout)
}

func selectRequests(requests []RequestSpec, options RunOptions, stdout, stderr io.Writer) ([]RequestSpec, error) {
	if options.Interactive {
		return interactiveSelection(requests, stdout, stderr)
	}
	if options.All {
		return requests, nil
	}

	var selected []RequestSpec
	if len(options.Indices) > 0 {
		for _, index := range options.Indices {
			if index < 1 || index > len(requests) {
				return nil, fmt.Errorf("request index %d out of range", index)
			}
			selected = append(selected, requests[index-1])
		}
	}
	if len(options.Names) > 0 {
		for _, name := range options.Names {
			found := false
			for _, request := range requests {
				if request.Name == name {
					selected = append(selected, request)
					found = true
				}
			}
			if !found {
				return nil, fmt.Errorf("request named %q not found", name)
			}
		}
	}
	if len(selected) > 0 {
		return dedupeRequests(selected), nil
	}
	if len(requests) == 1 {
		return requests, nil
	}
	return nil, errors.New("multiple requests found; use --all, --index, --name, or --interactive")
}

func interactiveSelection(requests []RequestSpec, stdout, stderr io.Writer) ([]RequestSpec, error) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Fprintln(stdout, "Available requests:")
		for i, request := range requests {
			fmt.Fprintf(stdout, "  %d) %s\n", i+1, request.Name)
		}
		fmt.Fprint(stdout, "Select request numbers, 'all', or 'q': ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)
		switch strings.ToLower(line) {
		case "q", "quit", "exit":
			return nil, errors.New("interactive session aborted")
		case "all":
			return requests, nil
		}
		indices, err := parseIndices(line)
		if err != nil {
			fmt.Fprintln(stderr, err)
			continue
		}
		options := RunOptions{Indices: indices}
		return selectRequests(requests, options, stdout, stderr)
	}
}

func parseIndices(value string) ([]int, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	indices := make([]int, 0, len(parts))
	for _, part := range parts {
		index, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("invalid request index %q", part)
		}
		indices = append(indices, index)
	}
	return indices, nil
}

func parseVarAssignments(values []string) (map[string]string, error) {
	result := map[string]string{}
	for _, value := range values {
		parts := strings.SplitN(value, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid variable assignment %q", value)
		}
		result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return result, nil
}

func dedupeRequests(requests []RequestSpec) []RequestSpec {
	seen := map[string]bool{}
	var result []RequestSpec
	for _, request := range requests {
		key := request.Name + "\x00" + request.Method + "\x00" + request.URL
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, request)
	}
	return result
}

func mustAbs(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}
