package app

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http/cookiejar"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(value string) error {
	*l = append(*l, value)
	return nil
}

func Run(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runWithContext(ctx, args, stdout, stderr)
}

func runWithContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	options, err := parseRunOptions(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := run(ctx, options, stdout, stderr); err != nil {
		if isCancellationError(err) {
			fmt.Fprintln(stderr, "cancelled")
			return 130
		}
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
		logLevel    string
		noColor     bool
		selfSigned  string
		insecure    bool
		all         bool
		interactive bool
	)
	stringFlagVar(fs, &names, "name", "n", "request name to execute")
	stringFlagVar(fs, &vars, "var", "v", "variable assignment key=value")
	stringFlag(fs, &indexes, "index", "x", "comma-separated request indexes (1-based)")
	stringFlag(fs, &configPath, "config", "c", "config file path")
	stringFlag(fs, &varsFile, "vars-file", "e", "JSON file containing variables")
	stringFlag(fs, &outputFile, "output", "o", "file to save the response body")
	stringFlag(fs, &bodyFile, "body-file", "b", "file to read the request body from")
	stringFlag(fs, &proxy, "proxy", "p", "proxy URL")
	stringFlag(fs, &httpVer, "http-version", "H", "HTTP version: auto, 1, 2, or 3")
	stringFlag(fs, &logLevel, "log-level", "l", "log level: none, error, info, debug, or trace")
	boolFlag(fs, &noColor, "no-color", "C", "disable colored output")
	stringFlag(fs, &selfSigned, "self-signed-cert", "s", "PEM file for a trusted self-signed server certificate")
	boolFlag(fs, &insecure, "insecure", "k", "skip TLS verification")
	boolFlag(fs, &all, "all", "a", "execute all requests in the .http file")
	boolFlag(fs, &interactive, "interactive", "i", "interactively choose requests to execute")
	if err := fs.Parse(args); err != nil {
		return RunOptions{}, err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		discovered, err := discoverImplicitHTTPFile(".")
		if err != nil {
			return RunOptions{}, err
		}
		rest = []string{discovered}
	}
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
		FilePath:           rest[0],
		ConfigPath:         configPath,
		VarsFile:           varsFile,
		Vars:               parsedVars,
		Names:              names,
		Indices:            indices,
		All:                all,
		Interactive:        interactive,
		BodyFile:           bodyFile,
		OutputFile:         outputFile,
		Proxy:              proxy,
		HTTPVersion:        httpVer,
		LogLevel:           logLevel,
		NoColor:            noColor,
		SelfSignedCertFile: selfSigned,
		Insecure:           insecure,
	}, nil
}

func stringFlag(fs *flag.FlagSet, target *string, long, short, usage string) {
	fs.StringVar(target, long, "", usage)
	fs.StringVar(target, short, "", usage)
}

func boolFlag(fs *flag.FlagSet, target *bool, long, short, usage string) {
	fs.BoolVar(target, long, false, usage)
	fs.BoolVar(target, short, false, usage)
}

func stringFlagVar(fs *flag.FlagSet, target flag.Value, long, short, usage string) {
	fs.Var(target, long, usage)
	fs.Var(target, short, usage)
}

func discoverImplicitHTTPFile(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	matches := make([]string, 0, 1)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.EqualFold(filepath.Ext(entry.Name()), ".http") {
			matches = append(matches, entry.Name())
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", errors.New("usage: gorc [flags] /absolute/or/relative/file.http")
	default:
		return "", errors.New("multiple .http files found in the current directory; specify one explicitly")
	}
}

func run(ctx context.Context, options RunOptions, stdout, stderr io.Writer) error {
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
	logLevel := cfg.LogLevel
	if options.LogLevel != "" {
		logLevel = options.LogLevel
	}
	noColor := cfg.NoColor || options.NoColor
	colorEnabled := !noColor
	colorizer := NewColorizer(colorEnabled)
	logger, err := NewLogger(logLevel, stderr, colorizer)
	if err != nil {
		return err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}

	runtime := RuntimeConfig{
		RootDir:            filepath.Dir(mustAbs(options.FilePath)),
		ConfigPath:         configPath,
		VarsFile:           varsPath,
		Config:             cfg,
		FileVars:           httpFile.FileVars,
		CLIVars:            options.Vars,
		CookieJar:          jar,
		Timeout:            timeout,
		OutputFile:         options.OutputFile,
		BodyFile:           options.BodyFile,
		Proxy:              options.Proxy,
		HTTPVersion:        options.HTTPVersion,
		LogLevel:           logLevel,
		ColorEnabled:       colorEnabled,
		Colorizer:          colorizer,
		SelfSignedCertFile: options.SelfSignedCertFile,
		Insecure:           options.Insecure,
		Auth:               options.SelectedAuth,
		Logger:             logger,
		LogWriter:          stderr,
	}

	if options.Interactive {
		return runInteractive(ctx, httpFile.Requests, runtime, stdout, stderr, os.Stdin)
	}

	selected, err := selectRequests(httpFile.Requests, options)
	if err != nil {
		return err
	}
	return executeRequests(ctx, buildExecutionPlans(selected, runtime), stdout)
}

func selectRequests(requests []RequestSpec, options RunOptions) ([]RequestSpec, error) {
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
		return selected, nil
	}
	if len(requests) == 1 {
		return requests, nil
	}
	return nil, errors.New("multiple requests found; use --all, --index, --name, or --interactive")
}

func runInteractive(ctx context.Context, requests []RequestSpec, runtime RuntimeConfig, stdout, stderr io.Writer, input io.Reader) error {
	reader := bufio.NewReader(input)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		selected, quit, err := interactiveSelection(requests, reader, stdout, stderr)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if quit {
			return nil
		}
		if err := executeRequests(ctx, buildExecutionPlans(selected, runtime), stdout); err != nil {
			return err
		}
	}
}

func interactiveSelection(requests []RequestSpec, reader *bufio.Reader, stdout, stderr io.Writer) ([]RequestSpec, bool, error) {
	for {
		fmt.Fprintln(stdout, "Available requests:")
		for i, request := range requests {
			fmt.Fprintf(stdout, "  %d) %s\n", i+1, request.Name)
		}
		fmt.Fprint(stdout, "Select request numbers, 'all', or 'q': ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, false, err
		}
		line = strings.TrimSpace(line)
		switch strings.ToLower(line) {
		case "q", "quit", "exit":
			return nil, true, nil
		case "all":
			return requests, false, nil
		}
		indices, err := parseIndices(line)
		if err != nil {
			fmt.Fprintln(stderr, err)
			continue
		}
		options := RunOptions{Indices: indices}
		selected, err := selectRequests(requests, options)
		if err != nil {
			fmt.Fprintln(stderr, err)
			continue
		}
		return selected, false, nil
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

func buildExecutionPlans(requests []RequestSpec, runtime RuntimeConfig) []executionPlan {
	plans := make([]executionPlan, 0, len(requests))
	for _, request := range requests {
		plans = append(plans, executionPlan{
			Request: request,
			Runtime: runtime,
		})
	}
	return plans
}

func mustAbs(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

func isCancellationError(err error) bool {
	return errors.Is(err, context.Canceled)
}
