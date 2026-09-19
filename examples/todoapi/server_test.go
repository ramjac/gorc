package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	godigest "github.com/icholy/digest"
	ntlm "github.com/jsthtlf/go-ntlm/nla/ntlm"
)

func newTestServer(t *testing.T) *demoServer {
	t.Helper()
	server, err := newDemoServer("127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0", log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestBasicAuthTodos(t *testing.T) {
	server := newTestServer(t)
	handler := server.routes()

	req := httptest.NewRequest(http.MethodGet, "/auth/basic/todos", nil)
	req.SetBasicAuth(basicUsername, basicPassword)
	resp := httptest.NewRecorder()

	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), `"auth":"basic"`) {
		t.Fatalf("unexpected response %s", resp.Body.String())
	}
}

func TestRequestLoggingIncludesSafeRequestAndAuthDetails(t *testing.T) {
	var logs bytes.Buffer
	server, err := newDemoServer("127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0", log.New(&logs, "", 0))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/basic/todos?include_done=true", nil)
	req.SetBasicAuth(basicUsername, basicPassword)
	resp := httptest.NewRecorder()
	server.routes().ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	for _, want := range []string{
		"method=GET",
		"path=/auth/basic/todos",
		"query=true",
		"auth=basic",
		"authorization=true",
		"status=200",
	} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("expected log to contain %q, got %q", want, logs.String())
		}
	}
	if strings.Contains(logs.String(), "include_done=true") || strings.Contains(logs.String(), basicPassword) {
		t.Fatalf("request logging exposed query values or credentials: %q", logs.String())
	}
}

func TestDigestAuthTodos(t *testing.T) {
	server := newTestServer(t)
	handler := server.routes()

	challengeReq := httptest.NewRequest(http.MethodGet, "/auth/digest/todos", nil)
	challengeResp := httptest.NewRecorder()
	handler.ServeHTTP(challengeResp, challengeReq)
	if challengeResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 challenge, got %d", challengeResp.Code)
	}
	challenge, err := godigest.ParseChallenge(challengeResp.Header().Get("WWW-Authenticate"))
	if err != nil {
		t.Fatal(err)
	}
	cred, err := godigest.Digest(challenge, godigest.Options{Method: http.MethodGet, URI: "/auth/digest/todos", Username: digestUsername, Password: digestPassword})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/digest/todos", nil)
	req.Header.Set("Authorization", cred.String())
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestAzureTokenFlow(t *testing.T) {
	server := newTestServer(t)
	handler := server.routes()

	body := strings.NewReader("grant_type=client_credentials&client_id=" + azureClientID + "&client_secret=" + azureClientSecret + "&scope=" + azureScope)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/v2.0/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	payload := map[string]any{}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["access_token"] != azureAccessToken {
		t.Fatalf("unexpected token payload %#v", payload)
	}
}

func TestAzureTokenRejectsUnexpectedScope(t *testing.T) {
	server := newTestServer(t)
	handler := server.routes()

	body := strings.NewReader("grant_type=client_credentials&client_id=" + azureClientID + "&client_secret=" + azureClientSecret + "&scope=api://wrong/.default")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/v2.0/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestNTLMAuthTodos(t *testing.T) {
	server := newTestServer(t)
	handler := server.routes()

	firstReq := httptest.NewRequest(http.MethodGet, "/auth/ntlm/todos", nil)
	firstReq.RemoteAddr = "127.0.0.1:7777"
	firstResp := httptest.NewRecorder()
	handler.ServeHTTP(firstResp, firstReq)
	if firstResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", firstResp.Code)
	}

	clientSession, err := ntlm.CreateClientSession(ntlm.Version2, ntlm.ConnectionlessMode)
	if err != nil {
		t.Fatal(err)
	}
	clientSession.SetUserInfo(ntlmUsername, ntlmPassword, ntlmDomain)
	negotiate, err := clientSession.GenerateNegotiateMessage()
	if err != nil {
		t.Fatal(err)
	}

	secondReq := httptest.NewRequest(http.MethodGet, "/auth/ntlm/todos", nil)
	secondReq.RemoteAddr = firstReq.RemoteAddr
	secondReq.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(negotiate.Serialize()))
	secondResp := httptest.NewRecorder()
	handler.ServeHTTP(secondResp, secondReq)
	if secondResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected challenge response, got %d body=%s", secondResp.Code, secondResp.Body.String())
	}
	challengeHeader := secondResp.Header().Get("WWW-Authenticate")
	challengePayload := strings.TrimSpace(strings.TrimPrefix(challengeHeader, "NTLM"))
	challengeBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(challengePayload))
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := ntlm.ParseChallengeMessage(challengeBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := clientSession.ProcessChallengeMessage(challenge); err != nil {
		t.Fatal(err)
	}
	authenticate, err := clientSession.GenerateAuthenticateMessage()
	if err != nil {
		t.Fatal(err)
	}

	thirdReq := httptest.NewRequest(http.MethodGet, "/auth/ntlm/todos", nil)
	thirdReq.RemoteAddr = firstReq.RemoteAddr
	thirdReq.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(authenticate.Serialize()))
	thirdResp := httptest.NewRecorder()
	handler.ServeHTTP(thirdResp, thirdReq)
	if thirdResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", thirdResp.Code, thirdResp.Body.String())
	}
}
