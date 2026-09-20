package app

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var requestLinePattern = regexp.MustCompile(`^([A-Z]+)\s+(\S+)(?:\s+(HTTP/\d(?:\.\d)?))?$`)

func parseHTTPFile(path string) (HTTPFile, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return HTTPFile{}, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return HTTPFile{}, err
	}

	sections, err := splitSections(string(data))
	if err != nil {
		return HTTPFile{}, err
	}
	result := HTTPFile{FileVars: map[string]string{}}

	for idx, section := range sections {
		spec, sectionVars, hasRequest, err := parseSection(section, abs)
		if err != nil {
			return HTTPFile{}, err
		}
		if !hasRequest {
			for key, value := range sectionVars {
				result.FileVars[key] = value
			}
			continue
		}
		if idx == 0 {
			for key, value := range sectionVars {
				result.FileVars[key] = value
			}
		}
		for key, value := range sectionVars {
			if spec.FileVars == nil {
				spec.FileVars = map[string]string{}
			}
			spec.FileVars[key] = value
		}
		result.Requests = append(result.Requests, spec)
	}

	return result, nil
}

func splitSections(content string) ([]string, error) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), len(content)+1)
	var sections []string
	var current []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "###" {
			sections = append(sections, strings.Join(current, "\n"))
			current = nil
			continue
		}
		current = append(current, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sections = append(sections, strings.Join(current, "\n"))
	return sections, nil
}

func parseSection(section, sourcePath string) (RequestSpec, map[string]string, bool, error) {
	lines := strings.Split(section, "\n")
	spec := RequestSpec{
		Headers:    http.Header{},
		FileVars:   map[string]string{},
		SourcePath: sourcePath,
	}
	vars := map[string]string{}
	state := "preamble"
	var bodyLines []string
	hasRequest := false

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		if state == "body" {
			bodyLines = append(bodyLines, line)
			continue
		}

		if trimmed == "" {
			if state == "headers" {
				state = "body"
			}
			continue
		}

		if state == "preamble" && strings.HasPrefix(trimmed, "@") {
			key, value, ok := parseAssignment(trimmed)
			if ok {
				vars[key] = value
				continue
			}
		}

		if state == "preamble" && strings.HasPrefix(trimmed, "#") {
			if err := parseDirective(&spec, trimmed); err != nil {
				return RequestSpec{}, nil, false, err
			}
			continue
		}

		if !hasRequest {
			matches := requestLinePattern.FindStringSubmatch(trimmed)
			if len(matches) != 4 {
				continue
			}
			hasRequest = true
			spec.Method = matches[1]
			spec.URL = matches[2]
			if matches[3] != "" {
				spec.HTTPVersion = normalizeHTTPVersion(strings.TrimPrefix(matches[3], "HTTP/"))
			}
			state = "headers"
			continue
		}

		if state == "headers" {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				return RequestSpec{}, nil, false, fmt.Errorf("invalid header line %q", line)
			}
			spec.Headers.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			continue
		}
	}

	if hasRequest {
		spec.Body = strings.Join(bodyLines, "\n")
		if spec.Name == "" {
			spec.Name = fmt.Sprintf("%s %s", spec.Method, spec.URL)
		}
	}

	return spec, vars, hasRequest, nil
}

func normalizeHTTPVersion(version string) string {
	switch {
	case strings.HasPrefix(version, "1."):
		return "1"
	case strings.HasPrefix(version, "2."):
		return "2"
	case strings.HasPrefix(version, "3."):
		return "3"
	default:
		return version
	}
}

func parseAssignment(line string) (string, string, bool) {
	parts := strings.SplitN(strings.TrimPrefix(line, "@"), "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

func parseDirective(spec *RequestSpec, line string) error {
	trimmed := strings.TrimSpace(strings.TrimPrefix(line, "#"))
	if !strings.HasPrefix(trimmed, "@") {
		return nil
	}
	fields := strings.Fields(strings.TrimPrefix(trimmed, "@"))
	if len(fields) == 0 {
		return nil
	}

	key := strings.ToLower(fields[0])
	value := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(trimmed, "@"+fields[0]), " "))
	switch key {
	case "name":
		spec.Name = value
	case "body-file":
		spec.BodyFile = value
	case "output":
		spec.OutputFile = value
	case "proxy":
		spec.Proxy = value
	case "http-version":
		spec.HTTPVersion = value
	case "ca-cert":
		spec.CACertFile = value
	case "self-signed-cert":
		spec.SelfSignedCertFile = value
	case "insecure":
		insecure, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid @insecure value %q: must be a boolean (true/false/1/0)", value)
		}
		spec.Insecure = insecure
		spec.InsecureSet = true
	case "auth":
		spec.Auth = parseAuthDirective(value)
	}
	return nil
}

var authKVFields = map[string]bool{
	"username":      true,
	"password":      true,
	"token":         true,
	"cert":          true,
	"cert_file":     true,
	"key":           true,
	"key_file":      true,
	"ca":            true,
	"ca_cert_file":  true,
	"tenant":        true,
	"tenant_id":     true,
	"client_id":     true,
	"client_secret": true,
	"scope":         true,
	"resource":      true,
	"token_url":     true,
}

func parseAuthDirective(value string) AuthConfig {
	fields := authFields(value)
	if len(fields) == 0 {
		return AuthConfig{}
	}
	auth := AuthConfig{Scheme: strings.ToLower(fields[0])}

	kv := map[string]string{}
	positional := make([]string, 0, len(fields)-1)
	for _, field := range fields[1:] {
		if idx := strings.Index(field, "="); idx > 0 && authKVFields[strings.ToLower(field[:idx])] {
			kv[strings.ToLower(field[:idx])] = field[idx+1:]
			continue
		}
		positional = append(positional, field)
	}

	if auth.Scheme == "bearer" {
		if token, ok := kv["token"]; ok {
			auth.Token = token
		} else {
			auth.Token = strings.Join(fields[1:], " ")
		}
		return auth
	}

	if username, ok := kv["username"]; ok {
		auth.Username = username
	}
	if password, ok := kv["password"]; ok {
		auth.Password = password
	}
	if token, ok := kv["token"]; ok {
		auth.Token = token
	}
	if cert, ok := kv["cert"]; ok {
		auth.CertFile = cert
	}
	if cert, ok := kv["cert_file"]; ok {
		auth.CertFile = cert
	}
	if key, ok := kv["key"]; ok {
		auth.KeyFile = key
	}
	if key, ok := kv["key_file"]; ok {
		auth.KeyFile = key
	}
	if ca, ok := kv["ca"]; ok {
		auth.CACertFile = ca
	}
	if ca, ok := kv["ca_cert_file"]; ok {
		auth.CACertFile = ca
	}
	if tenant, ok := kv["tenant"]; ok {
		auth.TenantID = tenant
	}
	if tenant, ok := kv["tenant_id"]; ok {
		auth.TenantID = tenant
	}
	if clientID, ok := kv["client_id"]; ok {
		auth.ClientID = clientID
	}
	if clientSecret, ok := kv["client_secret"]; ok {
		auth.ClientSecret = clientSecret
	}
	if scope, ok := kv["scope"]; ok {
		auth.Scope = scope
	}
	if resource, ok := kv["resource"]; ok {
		auth.Resource = resource
	}
	if tokenURL, ok := kv["token_url"]; ok {
		auth.TokenURL = tokenURL
	}

	// Consume remaining positional values in order: username first, then password.
	pos := 0
	if auth.Username == "" && pos < len(positional) {
		auth.Username = positional[pos]
		pos++
	}
	if auth.Password == "" && pos < len(positional) {
		auth.Password = positional[pos]
		pos++
	}

	return auth
}

func authFields(value string) []string {
	var fields []string
	var current strings.Builder
	depth := 0
	for _, char := range strings.TrimSpace(value) {
		switch char {
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		case ' ', '\t':
			if depth == 0 && current.Len() > 0 {
				fields = append(fields, current.String())
				current.Reset()
				continue
			}
		}
		current.WriteRune(char)
	}
	if current.Len() > 0 {
		fields = append(fields, current.String())
	}
	return fields
}
