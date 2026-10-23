package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func BenchmarkGetAzureToken(b *testing.B) {
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"token-value-1234567890-abcdefghijklmnopqrstuvwxyz"}`))
	}))
	defer tokenServer.Close()

	req := resolvedRequest{
		Timeout:     5 * time.Second,
		RequestSpec: RequestSpec{Insecure: true},
		Auth: AuthConfig{
			Scheme:       "azuread",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			Scope:        "https://vault.azure.net/.default",
			TokenURL:     tokenServer.URL,
		},
	}

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := getAzureToken(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func parseTokenResponseOld(r io.Reader) (string, error) {
	const maxTokenResponseSize = 1 << 20
	body, err := io.ReadAll(io.LimitReader(r, maxTokenResponseSize))
	if err != nil {
		return "", err
	}

	payload := struct {
		AccessToken string `json:"access_token"`
	}{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	return payload.AccessToken, nil
}

func parseTokenResponseNew(r io.Reader) (string, error) {
	const maxTokenResponseSize = 1 << 20
	payload := struct {
		AccessToken string `json:"access_token"`
	}{}
	if err := json.NewDecoder(io.LimitReader(r, maxTokenResponseSize)).Decode(&payload); err != nil {
		return "", err
	}
	return payload.AccessToken, nil
}

func BenchmarkParseTokenResponseOld(b *testing.B) {
	responseData := []byte(`{"access_token":"token-value-1234567890-abcdefghijklmnopqrstuvwxyz","token_type":"Bearer","expires_in":3599}`)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(responseData)
		_, err := parseTokenResponseOld(r)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseTokenResponseNew(b *testing.B) {
	responseData := []byte(`{"access_token":"token-value-1234567890-abcdefghijklmnopqrstuvwxyz","token_type":"Bearer","expires_in":3599}`)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(responseData)
		_, err := parseTokenResponseNew(r)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseLargeTokenResponseOld(b *testing.B) {
	padding := strings.Repeat("x", 100*1024)
	responseData := []byte(fmt.Sprintf(`{"access_token":"token-value","padding":"%s"}`, padding))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(responseData)
		_, err := parseTokenResponseOld(r)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseLargeTokenResponseNew(b *testing.B) {
	padding := strings.Repeat("x", 100*1024)
	responseData := []byte(fmt.Sprintf(`{"access_token":"token-value","padding":"%s"}`, padding))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(responseData)
		_, err := parseTokenResponseNew(r)
		if err != nil {
			b.Fatal(err)
		}
	}
}
