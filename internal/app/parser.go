package app

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var requestLinePattern = regexp.MustCompile(`^([A-Z]+)\s+(\S+)(?:\s+HTTP/\d(?:\.\d)?)?$`)

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

	for i := range result.Requests {
		for key, value := range result.FileVars {
			if result.Requests[i].FileVars == nil {
				result.Requests[i].FileVars = map[string]string{}
			}
			if _, exists := result.Requests[i].FileVars[key]; !exists {
				result.Requests[i].FileVars[key] = value
			}
		}
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
			parseDirective(&spec, trimmed)
			continue
		}

		if !hasRequest {
			matches := requestLinePattern.FindStringSubmatch(trimmed)
			if len(matches) != 3 {
				continue
			}
			hasRequest = true
			spec.Method = matches[1]
			spec.URL = matches[2]
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
		spec.Body = strings.TrimRight(strings.Join(bodyLines, "\n"), "\n")
		if spec.Name == "" {
			spec.Name = fmt.Sprintf("%s %s", spec.Method, spec.URL)
		}
	}

	return spec, vars, hasRequest, nil
}

func parseAssignment(line string) (string, string, bool) {
	parts := strings.SplitN(strings.TrimPrefix(line, "@"), "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

func parseDirective(spec *RequestSpec, line string) {
	trimmed := strings.TrimSpace(strings.TrimPrefix(line, "#"))
	if !strings.HasPrefix(trimmed, "@") {
		return
	}
	fields := strings.Fields(strings.TrimPrefix(trimmed, "@"))
	if len(fields) == 0 {
		return
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
		spec.Insecure = strings.EqualFold(value, "true") || value == "1" || strings.EqualFold(value, "yes")
	case "auth":
		spec.Auth = parseAuthDirective(value)
	}
}

func parseAuthDirective(value string) AuthConfig {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return AuthConfig{}
	}
	auth := AuthConfig{Scheme: strings.ToLower(fields[0])}
	kv := map[string]string{}
	for _, field := range fields[1:] {
		if parts := strings.SplitN(field, "=", 2); len(parts) == 2 {
			kv[strings.ToLower(parts[0])] = parts[1]
		}
	}
	if auth.Scheme == "bearer" && len(fields) > 1 && !strings.Contains(fields[1], "=") {
		auth.Token = strings.Join(fields[1:], " ")
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

	positional := make([]string, 0, len(fields)-1)
	for _, field := range fields[1:] {
		if strings.Contains(field, "=") {
			continue
		}
		positional = append(positional, field)
	}
	if auth.Scheme != "bearer" && len(positional) > 0 && auth.Username == "" {
		auth.Username = positional[0]
	}
	if auth.Scheme != "bearer" && auth.Password == "" {
		switch {
		case auth.Username != "" && len(positional) > 0:
			auth.Password = positional[len(positional)-1]
		case len(positional) > 1:
			auth.Password = positional[1]
		}
	}

	return auth
}
