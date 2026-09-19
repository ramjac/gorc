package gorc

import (
	"io"
	"net/http"
	"time"
)

type HTTPFile struct {
	FileVars map[string]string
	Requests []RequestSpec
}

type RequestSpec struct {
	Name               string
	Method             string
	URL                string
	Headers            http.Header
	Body               string
	BodyFile           string
	OutputFile         string
	Proxy              string
	HTTPVersion        string
	CACertFile         string
	SelfSignedCertFile string
	Insecure           bool
	Auth               AuthConfig
	FileVars           map[string]string
	SourcePath         string
}

type AuthConfig struct {
	Scheme       string `json:"scheme"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Token        string `json:"token"`
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	CACertFile   string `json:"ca_cert_file"`
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Scope        string `json:"scope"`
	Resource     string `json:"resource"`
	TokenURL     string `json:"token_url"`
}

type Config struct {
	Vars               map[string]string `json:"vars"`
	Proxy              string            `json:"proxy"`
	HTTPVersion        string            `json:"http_version"`
	LogLevel           string            `json:"log_level"`
	NoColor            bool              `json:"no_color"`
	Insecure           bool              `json:"insecure"`
	CACertFile         string            `json:"ca_cert_file"`
	SelfSignedCertFile string            `json:"self_signed_cert_file"`
	CertFile           string            `json:"cert_file"`
	KeyFile            string            `json:"key_file"`
	Timeout            string            `json:"timeout"`
	Auth               AuthConfig        `json:"auth"`
}

type RunOptions struct {
	FilePath           string
	ConfigPath         string
	VarsFile           string
	Vars               map[string]string
	Names              []string
	Indices            []int
	All                bool
	Interactive        bool
	BodyFile           string
	OutputFile         string
	Proxy              string
	HTTPVersion        string
	LogLevel           string
	NoColor            bool
	SelfSignedCertFile string
	Insecure           bool
	Timeout            time.Duration
	SelectedAuth       AuthConfig
}

type RuntimeConfig struct {
	RootDir            string
	ConfigPath         string
	VarsFile           string
	Config             Config
	FileVars           map[string]string
	CLIVars            map[string]string
	CookieJar          http.CookieJar
	Timeout            time.Duration
	OutputFile         string
	BodyFile           string
	Proxy              string
	HTTPVersion        string
	LogLevel           string
	ColorEnabled       bool
	Colorizer          *Colorizer
	SelfSignedCertFile string
	Insecure           bool
	Auth               AuthConfig
	Logger             *Logger
	LogWriter          io.Writer
}

type executionPlan struct {
	Request RequestSpec
	Runtime RuntimeConfig
}
