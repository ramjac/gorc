package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	godigest "github.com/icholy/digest"
	ntlm "github.com/jsthtlf/go-ntlm/nla/ntlm"
)

const (
	basicUsername     = "demo"
	basicPassword     = "basic-pass"
	bearerToken       = "todo-demo-bearer-token"
	digestUsername    = "digest-user"
	digestPassword    = "digest-pass"
	azureClientID     = "todo-demo-client"
	azureClientSecret = "todo-demo-secret"
	azureTenantID     = "todo-demo-tenant"
	azureScope        = "api://todo-demo/.default"
	azureResource     = "api://todo-demo"
	azureAccessToken  = "todo-demo-azure-access-token"
	ntlmUsername      = "demo"
	ntlmPassword      = "ntlm-pass"
	ntlmDomain        = "TODO"
	shutdownTimeout   = 5 * time.Second
)

var digestChallenge = godigest.Challenge{
	Realm:     "gorc-demo",
	Nonce:     "gorc-demo-nonce",
	Opaque:    "gorc-demo-opaque",
	QOP:       []string{"auth"},
	Algorithm: "MD5",
}

type contextKey string

const authSchemeKey contextKey = "auth-scheme"

type todo struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
	Done  bool   `json:"done"`
}

type todoStore struct {
	mu     sync.Mutex
	nextID int
	items  []todo
}

func newTodoStore() *todoStore {
	return &todoStore{
		nextID: 3,
		items: []todo{
			{ID: 1, Title: "show gorc against a self-signed server", Done: true},
			{ID: 2, Title: "exercise the auth endpoints", Done: false},
		},
	}
}

func (s *todoStore) list() []todo {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := make([]todo, len(s.items))
	copy(items, s.items)
	return items
}

func (s *todoStore) create(item todo) todo {
	s.mu.Lock()
	defer s.mu.Unlock()
	item.ID = s.nextID
	item.Done = false
	s.nextID++
	s.items = append(s.items, item)
	return item
}

type ntlmSessionStore struct {
	mu       sync.Mutex
	sessions map[string]ntlm.ServerSession
}

func newNTLMSessionStore() *ntlmSessionStore {
	return &ntlmSessionStore{sessions: map[string]ntlm.ServerSession{}}
}

func (s *ntlmSessionStore) set(key string, session ntlm.ServerSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[key] = session
}

func (s *ntlmSessionStore) get(key string) ntlm.ServerSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[key]
}

func (s *ntlmSessionStore) delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, key)
}

type demoServer struct {
	selfSignedAddr string
	caAddr         string
	mtlsAddr       string
	certs          certificateBundle
	store          *todoStore
	ntlm           *ntlmSessionStore
	logger         *log.Logger
}

func newDemoServer(selfSignedAddr, caAddr, mtlsAddr string, logger *log.Logger) (*demoServer, error) {
	certs, err := ensureCertificates(defaultCertificateDir(), certificateHosts(selfSignedAddr, caAddr, mtlsAddr))
	if err != nil {
		return nil, err
	}
	return &demoServer{
		selfSignedAddr: selfSignedAddr,
		caAddr:         caAddr,
		mtlsAddr:       mtlsAddr,
		certs:          certs,
		store:          newTodoStore(),
		ntlm:           newNTLMSessionStore(),
		logger:         logger,
	}, nil
}

func (s *demoServer) serve(ctx context.Context) error {
	handler := s.routes()
	mtlsConfig, err := s.mtlsTLSConfig()
	if err != nil {
		return err
	}

	servers := []func(context.Context) error{
		func(ctx context.Context) error {
			return serveServer(ctx, &http.Server{Addr: s.selfSignedAddr, Handler: handler}, s.logger, s.certs.SelfSignedCert, s.certs.SelfSignedKey)
		},
		func(ctx context.Context) error {
			return serveServer(ctx, &http.Server{Addr: s.caAddr, Handler: handler}, s.logger, s.certs.CAServerCert, s.certs.CAServerKey)
		},
		func(ctx context.Context) error {
			return serveServer(ctx, &http.Server{Addr: s.mtlsAddr, Handler: handler, TLSConfig: mtlsConfig}, s.logger, s.certs.CAServerCert, s.certs.CAServerKey)
		},
	}

	errCh := make(chan error, len(servers))
	for _, serve := range servers {
		go func(run func(context.Context) error) {
			errCh <- run(ctx)
		}(serve)
	}

	for range servers {
		err := <-errCh
		if err == nil || errors.Is(err, context.Canceled) {
			continue
		}
		return err
	}
	return ctx.Err()
}

func (s *demoServer) mtlsTLSConfig() (*tls.Config, error) {
	caPEM, err := os.ReadFile(s.certs.CACert)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("failed to append demo CA")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
	}, nil
}

func (s *demoServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/public/health", s.handleHealth)
	mux.HandleFunc("/oauth2/v2.0/token", s.handleAzureToken)
	mux.Handle("/auth/basic/todos", s.withAuth("basic", s.basicAuth(http.HandlerFunc(s.handleTodos))))
	mux.Handle("/auth/bearer/todos", s.withAuth("bearer", s.bearerAuth(bearerToken, http.HandlerFunc(s.handleTodos))))
	mux.Handle("/auth/digest/todos", s.withAuth("digest", s.digestAuth(http.HandlerFunc(s.handleTodos))))
	mux.Handle("/auth/ntlm/todos", s.withAuth("ntlm", s.ntlmAuth(http.HandlerFunc(s.handleTodos))))
	mux.Handle("/auth/azure/todos", s.withAuth("azuread", s.bearerAuth(azureAccessToken, http.HandlerFunc(s.handleTodos))))
	mux.Handle("/auth/mtls/todos", s.withAuth("mtls", s.mtlsAuth(http.HandlerFunc(s.handleTodos))))
	return mux
}

func (s *demoServer) withAuth(name string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), authSchemeKey, name)))
	})
}

func authScheme(r *http.Request) string {
	value, _ := r.Context().Value(authSchemeKey).(string)
	return value
}

func (s *demoServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":             "ok",
		"listener":           r.Host,
		"self_signed_base":   "https://" + s.selfSignedAddr,
		"ca_base":            "https://" + s.caAddr,
		"mtls_base":          "https://" + s.mtlsAddr,
		"supports":           []string{"basic", "bearer", "digest", "ntlm", "azuread", "mtls"},
		"generated_cert_dir": s.certs.Dir,
	})
}

func (s *demoServer) handleTodos(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		response := map[string]any{
			"auth":  authScheme(r),
			"todos": s.store.list(),
		}
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			response["client_common_name"] = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		writeJSON(w, http.StatusOK, response)
	case http.MethodPost:
		defer r.Body.Close()
		payload := struct {
			Title string `json:"title"`
		}{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		payload.Title = strings.TrimSpace(payload.Title)
		if payload.Title == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "title is required"})
			return
		}
		created := s.store.create(todo{Title: payload.Title})
		writeJSON(w, http.StatusCreated, map[string]any{"auth": authScheme(r), "todo": created})
	default:
		w.Header().Set("Allow", "GET, POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

func (s *demoServer) basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != basicUsername || password != basicPassword {
			w.Header().Set("WWW-Authenticate", `Basic realm="gorc-demo"`)
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "basic authentication required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *demoServer) bearerAuth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := strings.TrimSpace(r.Header.Get("Authorization"))
		if header != "Bearer "+token {
			w.Header().Set("WWW-Authenticate", strings.Join([]string{"Bearer", `realm="gorc-demo"`}, " "))
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "bearer token required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *demoServer) digestAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, godigest.Prefix) {
			s.writeDigestChallenge(w)
			return
		}
		cred, err := godigest.ParseCredentials(header)
		if err != nil {
			s.writeDigestChallenge(w)
			return
		}
		if cred.Username != digestUsername || cred.Realm != digestChallenge.Realm || cred.Nonce != digestChallenge.Nonce || cred.Opaque != digestChallenge.Opaque || cred.URI != r.URL.RequestURI() {
			s.writeDigestChallenge(w)
			return
		}
		expected, err := godigest.Digest(&digestChallenge, godigest.Options{
			Method:   r.Method,
			URI:      cred.URI,
			Username: digestUsername,
			Password: digestPassword,
			Count:    cred.Nc,
			Cnonce:   cred.Cnonce,
		})
		if err != nil || expected.Response != cred.Response || expected.QOP != cred.QOP {
			s.writeDigestChallenge(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *demoServer) writeDigestChallenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", digestChallenge.String())
	writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "digest authentication required"})
}

func (s *demoServer) ntlmAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, payload, ok := parseNTLMHeader(r.Header.Get("Authorization"))
		if !ok {
			s.writeNTLMChallengeHeader(w, "")
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "ntlm authentication required"})
			return
		}
		_ = scheme
		message, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			s.writeNTLMChallengeHeader(w, "")
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid ntlm payload"})
			return
		}

		switch ntlmMessageType(message) {
		case 1:
			session, err := ntlm.CreateServerSession(ntlm.Version2, ntlm.ConnectionlessMode)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}
			session.SetUserInfo(ntlmUsername, ntlmPassword, ntlmDomain)
			negotiate, err := ntlm.ParseNegotiateMessage(message)
			if err != nil {
				s.writeNTLMChallengeHeader(w, "")
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid ntlm negotiate message"})
				return
			}
			if err := session.ProcessNegotiateMessage(negotiate); err != nil {
				s.writeNTLMChallengeHeader(w, "")
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
				return
			}
			challenge, err := session.GenerateChallengeMessage()
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}
			s.ntlm.set(r.RemoteAddr, session)
			s.writeNTLMChallengeHeader(w, base64.StdEncoding.EncodeToString(challenge.Serialize()))
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "continue ntlm handshake"})
		case 3:
			session := s.ntlm.get(r.RemoteAddr)
			if session == nil {
				s.writeNTLMChallengeHeader(w, "")
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "missing ntlm session"})
				return
			}
			defer s.ntlm.delete(r.RemoteAddr)
			authenticate, err := ntlm.ParseAuthenticateMessage(message, session.Version())
			if err != nil {
				s.writeNTLMChallengeHeader(w, "")
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid ntlm authenticate message"})
				return
			}
			if err := session.ProcessAuthenticateMessage(authenticate); err != nil {
				s.writeNTLMChallengeHeader(w, "")
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "ntlm authentication failed"})
				return
			}
			next.ServeHTTP(w, r)
		default:
			s.writeNTLMChallengeHeader(w, "")
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unsupported ntlm message"})
		}
	})
}

func (s *demoServer) writeNTLMChallengeHeader(w http.ResponseWriter, payload string) {
	if payload == "" {
		w.Header().Add("WWW-Authenticate", "NTLM")
		return
	}
	w.Header().Add("WWW-Authenticate", "NTLM "+payload)
}

func parseNTLMHeader(header string) (string, string, bool) {
	header = strings.TrimSpace(header)
	for _, scheme := range []string{"NTLM ", "Negotiate "} {
		if strings.HasPrefix(header, scheme) {
			return strings.TrimSpace(strings.TrimSuffix(scheme, " ")), strings.TrimSpace(strings.TrimPrefix(header, scheme)), true
		}
	}
	return "", "", false
}

func ntlmMessageType(message []byte) uint32 {
	if len(message) < 12 || string(message[:8]) != "NTLMSSP\x00" {
		return 0
	}
	return binary.LittleEndian.Uint32(message[8:12])
}

func (s *demoServer) mtlsAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "client certificate required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *demoServer) handleAzureToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if r.Form.Get("grant_type") != "client_credentials" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "grant_type must be client_credentials"})
		return
	}
	if r.Form.Get("client_id") != azureClientID || r.Form.Get("client_secret") != azureClientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid client credentials"})
		return
	}
	scope := r.Form.Get("scope")
	resource := r.Form.Get("resource")
	if scope == "" && resource == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "scope or resource is required"})
		return
	}
	if scope != "" && scope != azureScope {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unexpected scope"})
		return
	}
	if resource != "" && resource != azureResource {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unexpected resource"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": azureAccessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
