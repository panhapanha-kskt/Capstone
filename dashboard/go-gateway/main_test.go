package main

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func testGateway(t *testing.T) (*gateway, *httptest.Server) {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-SOC-Internal-Token") != "internal-secret-01234567890123456789" {
			t.Error("missing internal token")
		}
		if r.Header.Get("Cookie") != "" {
			t.Error("browser cookie forwarded")
		}
		if r.Header.Get("Sec-Fetch-Site") != "same-origin" {
			t.Error("untrusted browser site hint forwarded")
		}
		if r.URL.Path == "/api/analysts" {
			_ = json.NewEncoder(w).Encode(map[string]any{"records": []map[string]string{{"id": "analyst-1"}, {"id": "analyst-2"}}, "authenticated": false})
			return
		}
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			_, _ = w.Write(b)
			return
		}
		_, _ = w.Write([]byte(r.URL.RawQuery))
	}))
	t.Cleanup(backend.Close)
	u, _ := url.Parse(backend.URL)
	salt := []byte("0123456789abcdef")
	hash, _ := pbkdf2.Key(sha256.New, "TestPassword!123", salt, 1, 32)
	tokenHash := sha256.Sum256([]byte("0123456789abcdef0123456789abcdef"))
	g, err := newGateway(backend.URL, "internal-secret-01234567890123456789", []credential{{Username: "analyst-1", Analyst: "analyst-1", SaltHex: hex.EncodeToString(salt), HashHex: hex.EncodeToString(hash), TokenSHA256: hex.EncodeToString(tokenHash[:]), Iterations: 1}}, false)
	if err != nil {
		t.Fatal(err)
	}
	g.backend = u
	return g, backend
}
func loginRequest(t *testing.T, g *gateway) *http.Cookie {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "http://localhost/login", strings.NewReader(url.Values{"username": {"analyst-1"}, "password": {"TestPassword!123"}, "access_token": {"0123456789abcdef0123456789abcdef"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatalf("login status %d: %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
				t.Fatal("session cookie flags missing")
			}
			return c
		}
	}
	t.Fatal("missing session cookie")
	return nil
}
func TestAuthenticationAndActorBinding(t *testing.T) {
	g, _ := testGateway(t)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest("GET", "http://localhost/api/alerts", nil))
	if w.Code != 401 {
		t.Fatalf("anonymous read got %d", w.Code)
	}
	c := loginRequest(t, g)
	r := httptest.NewRequest("POST", "http://localhost/api/alerts/bulk", bytes.NewBufferString(`{"actor":"analyst-2","note":"ok"}`))
	r.AddCookie(c)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://localhost")
	r.Header.Set("Sec-Fetch-Site", "same-site")
	r.Header.Set("X-SOC-Internal-Token", "attacker-value")
	w = httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("write got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["actor"] != "analyst-1" {
		t.Fatalf("spoofed actor accepted: %v", body)
	}
}
func TestReadActorAndAnalystIsolation(t *testing.T) {
	g, _ := testGateway(t)
	c := loginRequest(t, g)
	r := httptest.NewRequest("GET", "http://localhost/api/triage/me?actor=analyst-2", nil)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "actor=analyst-1") {
		t.Fatalf("actor query not bound: %s", w.Body.String())
	}
	r = httptest.NewRequest("GET", "http://localhost/api/analysts", nil)
	r.AddCookie(c)
	w = httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), "analyst-2") || !strings.Contains(w.Body.String(), `"authenticated":true`) {
		t.Fatalf("analyst list exposed: %s", w.Body.String())
	}
}
func TestRejectCrossOriginAndOversize(t *testing.T) {
	g, _ := testGateway(t)
	c := loginRequest(t, g)
	r := httptest.NewRequest("POST", "http://localhost/api/alerts/bulk", strings.NewReader(`{}`))
	r.AddCookie(c)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("cross origin got %d", w.Code)
	}
	r = httptest.NewRequest("POST", "http://localhost/api/alerts/bulk", strings.NewReader(`{"note":"`+strings.Repeat("a", maxJSONBody)+`"}`))
	r.AddCookie(c)
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("oversize body got %d", w.Code)
	}
}
func TestRejectDNSRebindingHost(t *testing.T) {
	g, _ := testGateway(t)
	r := httptest.NewRequest("GET", "http://attacker.example/login", nil)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("unexpected Host accepted: %d", w.Code)
	}
}

func TestExactOriginWinsOverSameSiteHint(t *testing.T) {
	r := httptest.NewRequest("POST", "http://127.0.0.1:9000/login", nil)
	r.Header.Set("Origin", "http://127.0.0.1:9000")
	r.Header.Set("Sec-Fetch-Site", "same-site")
	if !sameOrigin(r) {
		t.Fatal("exact matching Origin rejected")
	}
	r.Header.Set("Origin", "http://attacker.example")
	if sameOrigin(r) {
		t.Fatal("foreign Origin accepted")
	}
}

func TestOpaqueOriginAllowedOnlyForLogin(t *testing.T) {
	g, _ := testGateway(t)
	r := httptest.NewRequest("POST", "http://localhost/login", strings.NewReader(url.Values{"username": {"analyst-1"}, "password": {"TestPassword!123"}, "access_token": {"0123456789abcdef0123456789abcdef"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "null")
	r.Header.Set("Sec-Fetch-Site", "none")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatalf("opaque login got %d: %s", w.Code, w.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("missing session cookie")
	}
	r = httptest.NewRequest("POST", "http://localhost/api/alerts/00000000/acknowledge", strings.NewReader(`{}`))
	r.AddCookie(sessionCookie)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "null")
	r.Header.Set("Sec-Fetch-Site", "none")
	w = httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("opaque SOC write got %d", w.Code)
	}
}

func TestOpaqueOriginWithSameOriginMetadata(t *testing.T) {
	g, _ := testGateway(t)
	r := httptest.NewRequest("POST", "http://localhost/login", strings.NewReader(url.Values{"username": {"analyst-1"}, "password": {"TestPassword!123"}, "access_token": {"0123456789abcdef0123456789abcdef"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "null")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatalf("browser form login got %d: %s", w.Code, w.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("missing session cookie")
	}
	r = httptest.NewRequest("POST", "http://localhost/api/alerts/00000000/acknowledge", strings.NewReader(`{}`))
	r.AddCookie(cookie)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "null")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w = httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("same-origin browser POST got %d: %s", w.Code, w.Body.String())
	}
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	if sameOrigin(r) {
		t.Fatal("cross-site opaque origin accepted")
	}
}

func TestPasswordPolicyAndLoginRateLimit(t *testing.T) {
	if remoteIP("127.0.0.1:1234") != remoteIP("127.0.0.1:5678") {
		t.Fatal("login rate limit must ignore ephemeral source ports")
	}
	for _, password := range []string{"Short!1", "NoNumbersHere!", "NoSymbols1234", "1234567890!@"} {
		if validPassword(password) {
			t.Fatalf("accepted weak password %q", password)
		}
	}
	if !validPassword("TestPassword!123") {
		t.Fatal("rejected valid password")
	}
	g, _ := testGateway(t)
	for i := 0; i < 5; i++ {
		r := httptest.NewRequest("POST", "http://localhost/login", strings.NewReader(url.Values{"username": {"analyst-1"}, "password": {"WrongPassword!123"}, "access_token": {"0123456789abcdef0123456789abcdef"}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("failed attempt %d got %d", i, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "http://localhost/login", strings.NewReader(url.Values{"username": {"analyst-1"}, "password": {"TestPassword!123"}, "access_token": {"0123456789abcdef0123456789abcdef"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatalf("rate limit got %d", w.Code)
	}
}

func TestLoginRequiresMatchingToken(t *testing.T) {
	g, _ := testGateway(t)
	for _, form := range []url.Values{
		{"username": {"analyst-1"}, "password": {"TestPassword!123"}, "access_token": {"fedcba9876543210fedcba9876543210"}},
		{"username": {"analyst-1"}, "password": {"TestPassword!123"}},
		{"access_token": {"0123456789abcdef0123456789abcdef"}},
	} {
		r := httptest.NewRequest("POST", "http://localhost/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("incomplete or mismatched credentials got %d", w.Code)
		}
	}
}
