package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http/cookiejar"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

const usageText = "usage: gorc [flags] /absolute/or/relative/file.http"

type cliParser struct {
	cmd         *cobra.Command
	names       []string
	vars        []string
	indexes     string
	configPath  string
	varsFile    string
	outputFile  string
	bodyFile    string
	proxy       string
	httpVersion string
	logLevel    string
	noColor     bool
	selfSigned  string
	insecure    bool
	all         bool
	interactive bool
	parsed      RunOptions
}

type usageError struct {
	err error
}

func (e usageError) Error() string {
	return e.err.Error()
}

func (e usageError) Unwrap() error {
	return e.err
}

func Run(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runWithContext(ctx, args, stdout, stderr)
}

func runWithContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	parser := newCLIParser(stdout, stderr, func(ctx context.Context, options RunOptions) error {
		return run(ctx, options, stdout, stderr)
	})
	parser.cmd.SetArgs(args)
	parser.cmd.SetContext(ctx)
	if err := parser.cmd.Execute(); err != nil {
		if isCancellationError(err) {
			fmt.Fprintln(stderr, "cancelled")
			return 130
		}
		if isUsageError(err) {
			fmt.Fprintln(stderr, err)
			return 2
		}
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func parseRunOptions(args []string) (RunOptions, error) {
	parser := newCLIParser(io.Discard, io.Discard, nil)
	parser.cmd.SetArgs(args)
	if err := parser.cmd.Execute(); err != nil {
		return RunOptions{}, err
	}
	return parser.parsed, nil
}

func newCLIParser(stdout, stderr io.Writer, runner func(context.Context, RunOptions) error) *cliParser {
	parser := &cliParser{}
	cmd := &cobra.Command{
		Use:   "gorc [flags] /absolute/or/relative/file.http",
		Short: "Execute REST requests defined in .http files",
		Long: "gorc executes one or more REST requests defined in a .http file.\n\n" +
			"If no file is provided and the current directory contains exactly one .http file, gorc uses it automatically. " +
			"For multi-request files, use --all, --index, --name, or --interactive to choose which requests to run.",
		Example: strings.Join([]string{
			"gorc requests.http",
			"gorc --all requests.http",
			"gorc --name login --name profile requests.http",
			"gorc --interactive requests.http",
			"gorc --config gorc.json requests.http",
		}, "\n"),
		SilenceErrors:         true,
		SilenceUsage:          true,
		DisableFlagsInUseLine: true,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := parser.buildOptions(args)
			if err != nil {
				return err
			}
			parser.parsed = options
			if runner == nil {
				return nil
			}
			return runner(cmd.Context(), options)
		},
	}
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageError{err: err}
	})

	flags := cmd.Flags()
	flags.StringArrayVarP(&parser.names, "name", "n", nil, "request name to execute")
	flags.StringArrayVarP(&parser.vars, "var", "v", nil, "variable assignment key=value")
	flags.StringVarP(&parser.indexes, "index", "x", "", "comma-separated request indexes (1-based)")
	flags.StringVarP(&parser.configPath, "config", "c", "", "config file path")
	flags.StringVarP(&parser.varsFile, "vars-file", "e", "", "JSON file containing variables")
	flags.StringVarP(&parser.outputFile, "output", "o", "", "file to save the response body")
	flags.StringVarP(&parser.bodyFile, "body-file", "b", "", "file to read the request body from")
	flags.StringVarP(&parser.proxy, "proxy", "p", "", "proxy URL")
	flags.StringVarP(&parser.httpVersion, "http-version", "H", "", "HTTP version: auto, 1, 2, or 3")
	flags.StringVarP(&parser.logLevel, "log-level", "l", "", "log level: none, error, info, debug, or trace")
	flags.BoolVarP(&parser.noColor, "no-color", "C", false, "disable colored output")
	flags.StringVarP(&parser.selfSigned, "self-signed-cert", "s", "", "PEM file for a trusted self-signed server certificate")
	flags.BoolVarP(&parser.insecure, "insecure", "k", false, "skip TLS verification")
	flags.BoolVarP(&parser.all, "all", "a", false, "execute all requests in the .http file")
	flags.BoolVarP(&parser.interactive, "interactive", "i", false, "interactively choose requests to execute")

	parser.cmd = cmd
	return parser
}

func (p *cliParser) buildOptions(args []string) (RunOptions, error) {
	var filePath string
	switch len(args) {
	case 0:
		discovered, err := discoverImplicitHTTPFile(".")
		if err != nil {
			return RunOptions{}, usageError{err: err}
		}
		filePath = discovered
	case 1:
		filePath = args[0]
	default:
		return RunOptions{}, usageError{err: errors.New(usageText)}
	}

	indices, err := parseIndices(p.indexes)
	if err != nil {
		return RunOptions{}, usageError{err: err}
	}
	parsedVars, err := parseVarAssignments(p.vars)
	if err != nil {
		return RunOptions{}, usageError{err: err}
	}

	return RunOptions{
		FilePath:           filePath,
		ConfigPath:         p.configPath,
		VarsFile:           p.varsFile,
		Vars:               parsedVars,
		Names:              p.names,
		Indices:            indices,
		All:                p.all,
		Interactive:        p.interactive,
		BodyFile:           p.bodyFile,
		OutputFile:         p.outputFile,
		Proxy:              p.proxy,
		HTTPVersion:        p.httpVersion,
		LogLevel:           p.logLevel,
		NoColor:            p.noColor,
		SelfSignedCertFile: p.selfSigned,
		Insecure:           p.insecure,
	}, nil
}

func isUsageError(err error) bool {
	var target usageError
	return errors.As(err, &target)
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
		return "", errors.New(usageText)
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
		VarsFileVars:       varsFile,
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
		outputFiles:        newOutputFileState(),
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
	if runtime.outputFiles == nil {
		runtime.outputFiles = newOutputFileState()
	}
	reader := bufio.NewReader(input)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		selected, quit, err := interactiveSelection(ctx, requests, reader, input, stdout, stderr)
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

func interactiveSelection(ctx context.Context, requests []RequestSpec, reader *bufio.Reader, input io.Reader, stdout, stderr io.Writer) ([]RequestSpec, bool, error) {
	for {
		fmt.Fprintln(stdout, "Available requests:")
		for i, request := range requests {
			fmt.Fprintf(stdout, "  %d) %s\n", i+1, request.Name)
		}
		fmt.Fprint(stdout, "Select request numbers, 'all', or 'q': ")
		type inputResult struct {
			line string
			err  error
		}
		result := make(chan inputResult, 1)
		go func() {
			line, err := reader.ReadString('\n')
			result <- inputResult{line: line, err: err}
		}()
		var line string
		select {
		case <-ctx.Done():
			if closer, ok := input.(io.Closer); ok {
				_ = closer.Close()
			}
			return nil, false, ctx.Err()
		case input := <-result:
			if input.err != nil {
				return nil, false, input.err
			}
			line = input.line
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
