package app

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
	Scheme       string `json:"scheme" mapstructure:"scheme"`
	Username     string `json:"username" mapstructure:"username"`
	Password     string `json:"password" mapstructure:"password"`
	Token        string `json:"token" mapstructure:"token"`
	CertFile     string `json:"cert_file" mapstructure:"cert_file"`
	KeyFile      string `json:"key_file" mapstructure:"key_file"`
	CACertFile   string `json:"ca_cert_file" mapstructure:"ca_cert_file"`
	TenantID     string `json:"tenant_id" mapstructure:"tenant_id"`
	ClientID     string `json:"client_id" mapstructure:"client_id"`
	ClientSecret string `json:"client_secret" mapstructure:"client_secret"`
	Scope        string `json:"scope" mapstructure:"scope"`
	Resource     string `json:"resource" mapstructure:"resource"`
	TokenURL     string `json:"token_url" mapstructure:"token_url"`
}

type Config struct {
	Vars               map[string]string `json:"vars" mapstructure:"vars"`
	Proxy              string            `json:"proxy" mapstructure:"proxy"`
	HTTPVersion        string            `json:"http_version" mapstructure:"http_version"`
	LogLevel           string            `json:"log_level" mapstructure:"log_level"`
	NoColor            bool              `json:"no_color" mapstructure:"no_color"`
	Insecure           bool              `json:"insecure" mapstructure:"insecure"`
	CACertFile         string            `json:"ca_cert_file" mapstructure:"ca_cert_file"`
	SelfSignedCertFile string            `json:"self_signed_cert_file" mapstructure:"self_signed_cert_file"`
	CertFile           string            `json:"cert_file" mapstructure:"cert_file"`
	KeyFile            string            `json:"key_file" mapstructure:"key_file"`
	Timeout            string            `json:"timeout" mapstructure:"timeout"`
	Auth               AuthConfig        `json:"auth" mapstructure:"auth"`
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
