package main

import (
	"bytes"
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const maxJSONBody = 64 << 10
const cookieName = "soc_session"
const minPasswordIterations = 600000

type credential struct {
	Username    string `json:"username"`
	Analyst     string `json:"analyst"`
	SaltHex     string `json:"salt_hex"`
	HashHex     string `json:"hash_hex"`
	TokenSHA256 string `json:"token_sha256"`
	Iterations  int    `json:"iterations"`
}
type loginAttempt struct {
	count int
	until time.Time
}
type session struct {
	analyst string
	expires time.Time
}
type actorContextKey struct{}
type gateway struct {
	backend       *url.URL
	proxy         *httputil.ReverseProxy
	internalToken string
	credentials   []credential
	secureCookie  bool
	publicHost    string
	mu            sync.Mutex
	sessions      map[string]session
	loginAttempts map[string]loginAttempt
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func loadCredentials(path string) ([]credential, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var records []credential
	if err := json.Unmarshal(b, &records); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("at least one credential is required")
	}
	seen := map[string]bool{}
	for _, c := range records {
		if c.Username == "" || len(c.Username) > 80 || c.Analyst == "" || seen[c.Username] || c.Iterations < minPasswordIterations || c.Iterations > 2000000 {
			return nil, errors.New("invalid or duplicate credential")
		}
		salt, saltErr := hex.DecodeString(c.SaltHex)
		hash, hashErr := hex.DecodeString(c.HashHex)
		tokenHash, tokenErr := hex.DecodeString(c.TokenSHA256)
		if saltErr != nil || hashErr != nil || tokenErr != nil || len(salt) < 16 || len(hash) != 32 || len(tokenHash) != 32 {
			return nil, errors.New("invalid password hash record")
		}
		seen[c.Username] = true
	}
	return records, nil
}

func newGateway(backend, secret string, credentials []credential, secure bool) (*gateway, error) {
	u, err := url.Parse(backend)
	if err != nil || u.Scheme != "http" || u.Hostname() == "" {
		return nil, errors.New("backend must be a loopback HTTP URL")
	}
	if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
		return nil, errors.New("backend must use a loopback IP address")
	}
	if len(secret) < 32 {
		return nil, errors.New("SOC_INTERNAL_TOKEN must be at least 32 characters")
	}
	g := &gateway{backend: u, internalToken: secret, credentials: credentials, secureCookie: secure, sessions: map[string]session{}, loginAttempts: map[string]loginAttempt{}}
	g.proxy = httputil.NewSingleHostReverseProxy(u)
	g.proxy.Transport = &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 16, ResponseHeaderTimeout: 30 * time.Second}
	g.proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		jsonError(w, http.StatusBadGateway, "Python backend unavailable")
	}
	g.proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.Request.URL.Path != "/api/analysts" || resp.StatusCode != 200 {
			return nil
		}
		actor, _ := resp.Request.Context().Value(actorContextKey{}).(string)
		defer resp.Body.Close()
		var payload struct {
			Records []map[string]any `json:"records"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
			return err
		}
		filtered := make([]map[string]any, 0, 1)
		for _, record := range payload.Records {
			if record["id"] == actor {
				filtered = append(filtered, record)
			}
		}
		b, err := json.Marshal(map[string]any{"records": filtered, "authenticated": true})
		if err != nil {
			return err
		}
		resp.Body = io.NopCloser(bytes.NewReader(b))
		resp.ContentLength = int64(len(b))
		resp.Header.Set("Content-Length", fmt.Sprint(len(b)))
		resp.Header.Del("ETag")
		return nil
	}
	return g, nil
}

func securityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
}
func jsonError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	site := r.Header.Get("Sec-Fetch-Site")
	if origin != "" {
		// An exact Origin is stronger evidence than Sec-Fetch-Site. Some browser
		// contexts report "same-site" even for a request to this exact host.
		// An opaque Origin is acceptable only when the browser's protected
		// Fetch Metadata header says the request came from this exact origin.
		if origin == "null" {
			return site == "same-origin"
		}
		return origin == "http://"+r.Host || origin == "https://"+r.Host
	}
	return site == "" || site == "same-origin" || site == "none"
}
func loginOriginAllowed(r *http.Request) bool {
	// A direct browser navigation may submit a form from an opaque origin.
	// Browsers mark this as Origin: null plus Sec-Fetch-Site: none. This
	// exception applies only to credential sign-in, never to SOC write routes.
	return sameOrigin(r) || (r.Header.Get("Origin") == "null" && r.Header.Get("Sec-Fetch-Site") == "none")
}
func validPassword(password string) bool {
	if len(password) > 256 || !utf8.ValidString(password) || utf8.RuneCountInString(password) < 12 {
		return false
	}
	letter, number, symbol := false, false, false
	for _, char := range password {
		letter = letter || unicode.IsLetter(char)
		number = number || unicode.IsDigit(char)
		symbol = symbol || unicode.IsPunct(char) || unicode.IsSymbol(char)
	}
	return letter && number && symbol
}
func (g *gateway) verifyCredentials(username, password, token string) string {
	if len(username) == 0 || len(username) > 80 || !validPassword(password) || len(token) < 32 || len(token) > 256 {
		return ""
	}
	tokenSum := sha256.Sum256([]byte(token))
	for _, c := range g.credentials {
		if c.Username != username {
			continue
		}
		salt, _ := hex.DecodeString(c.SaltHex)
		want, _ := hex.DecodeString(c.HashHex)
		wantToken, _ := hex.DecodeString(c.TokenSHA256)
		got, err := pbkdf2.Key(sha256.New, password, salt, c.Iterations, len(want))
		if err == nil && subtle.ConstantTimeCompare(got, want) == 1 && subtle.ConstantTimeCompare(tokenSum[:], wantToken) == 1 {
			return c.Analyst
		}
	}
	return ""
}
func (g *gateway) loginLimited(remote string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	a := g.loginAttempts[remote]
	if time.Now().After(a.until) {
		delete(g.loginAttempts, remote)
		return false
	}
	return a.count >= 5
}
func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}
func (g *gateway) loginFailed(remote string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	a := g.loginAttempts[remote]
	if time.Now().After(a.until) {
		a = loginAttempt{until: time.Now().Add(5 * time.Minute)}
	}
	a.count++
	g.loginAttempts[remote] = a
}
func (g *gateway) hostAllowed(hostport string) bool {
	host := hostport
	if parsed, _, err := net.SplitHostPort(hostport); err == nil {
		host = parsed
	}
	host = strings.Trim(host, "[]")
	if g.publicHost != "" {
		return strings.EqualFold(host, g.publicHost)
	}
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
func (g *gateway) identity(r *http.Request) string {
	c, err := r.Cookie(cookieName)
	if err != nil || len(c.Value) != 64 {
		return ""
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.sessions[c.Value]
	if !ok {
		return ""
	}
	if time.Now().After(s.expires) {
		delete(g.sessions, c.Value)
		return ""
	}
	return s.analyst
}
func (g *gateway) login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		_, _ = io.WriteString(w, `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SOC sign in</title><style>body{min-height:100vh;display:grid;place-items:center;background:#08111c;color:#edf5ff;font:16px system-ui}main{width:min(400px,90vw);padding:32px;border:1px solid #36506a;border-radius:18px;background:#102136;box-shadow:0 24px 80px #0008}h1{margin-top:0}label,input,button{display:block;width:100%;box-sizing:border-box}input{margin:10px 0 18px;padding:14px;border-radius:9px;border:1px solid #55718c;background:#081827;color:white}button{padding:14px;border:0;border-radius:9px;background:#41c7dc;color:#071522;font-weight:700;cursor:pointer}.hint{color:#b4c8dd;font-size:13px;margin:0 0 20px}</style><main><h1>SOC sign in</h1><p>Enter your analyst username, password, and access token.</p><form method="post" action="/login"><label for="username">Username</label><input id="username" name="username" type="text" autocomplete="username" maxlength="80" required><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" minlength="12" maxlength="256" pattern="(?=.*[A-Za-z])(?=.*[0-9])(?=.*[^A-Za-z0-9]).{12,}" required><p class="hint">At least 12 characters with a letter, number, and symbol.</p><label for="access_token">Access token</label><input id="access_token" name="access_token" type="password" autocomplete="off" minlength="32" maxlength="256" required><button>Sign in</button></form></main></html>`)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		jsonError(w, 405, "method not allowed")
		return
	}
	if !loginOriginAllowed(r) {
		log.Printf("rejected login origin: host=%q origin=%q site=%q", r.Host, r.Header.Get("Origin"), r.Header.Get("Sec-Fetch-Site"))
		jsonError(w, 403, "cross-origin request rejected")
		return
	}
	client := remoteIP(r.RemoteAddr)
	if g.loginLimited(client) {
		w.Header().Set("Retry-After", "300")
		jsonError(w, 429, "too many sign-in attempts; try again later")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		jsonError(w, 400, "invalid form")
		return
	}
	analyst := g.verifyCredentials(r.PostForm.Get("username"), r.PostForm.Get("password"), r.PostForm.Get("access_token"))
	if analyst == "" {
		g.loginFailed(client)
		jsonError(w, 401, "invalid credentials")
		return
	}
	g.mu.Lock()
	delete(g.loginAttempts, client)
	g.mu.Unlock()
	sid, err := randomToken()
	if err != nil {
		jsonError(w, 500, "session unavailable")
		return
	}
	g.mu.Lock()
	g.sessions[sid] = session{analyst, time.Now().Add(8 * time.Hour)}
	g.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: sid, Path: "/", HttpOnly: true, Secure: g.secureCookie, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 3600})
	http.Redirect(w, r, "/soc", http.StatusSeeOther)
}
func (g *gateway) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !sameOrigin(r) {
		jsonError(w, 403, "request rejected")
		return
	}
	if c, err := r.Cookie(cookieName); err == nil {
		g.mu.Lock()
		delete(g.sessions, c.Value)
		g.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", HttpOnly: true, Secure: g.secureCookie, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if !g.hostAllowed(r.Host) {
		jsonError(w, 403, "Host header not allowed")
		return
	}
	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
		return
	}
	if r.URL.Path == "/login" {
		g.login(w, r)
		return
	}
	if r.URL.Path == "/logout" {
		g.logout(w, r)
		return
	}
	actor := g.identity(r)
	if actor == "" {
		if r.Method == http.MethodGet && !strings.HasPrefix(r.URL.Path, "/api/") {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		} else {
			jsonError(w, 401, "authentication required")
		}
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodHead {
		jsonError(w, 405, "method not allowed")
		return
	}
	if r.Method == http.MethodPost && !sameOrigin(r) {
		log.Printf("rejected POST origin: path=%q host=%q origin=%q site=%q", r.URL.Path, r.Host, r.Header.Get("Origin"), r.Header.Get("Sec-Fetch-Site"))
		jsonError(w, 403, "cross-origin request rejected")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") && r.Method == http.MethodPost && !strings.HasPrefix(r.URL.Path, "/training/") {
		if strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])) != "application/json" {
			jsonError(w, 415, "JSON required")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
		var body map[string]json.RawMessage
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&body); err != nil || body == nil {
			jsonError(w, 400, "invalid JSON object")
			return
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			jsonError(w, 400, "trailing JSON data")
			return
		}
		for key := range body {
			if strings.HasPrefix(key, "_") {
				delete(body, key)
			}
		}
		value, _ := json.Marshal(actor)
		body["actor"] = value
		encoded, _ := json.Marshal(body)
		r.Body = io.NopCloser(bytes.NewReader(encoded))
		r.ContentLength = int64(len(encoded))
	}
	if strings.HasPrefix(r.URL.Path, "/api/") && r.Method == http.MethodGet {
		q := r.URL.Query()
		if q.Has("actor") {
			q.Set("actor", actor)
			r.URL.RawQuery = q.Encode()
		}
	}
	// Never forward client-supplied internal or identity headers.
	r.Header.Del("X-SOC-Internal-Token")
	r.Header.Del("X-Authenticated-User")
	r.Header.Del("Cookie")
	r.Header.Del("Origin") // same-origin was checked against the public gateway host above.
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("X-SOC-Internal-Token", g.internalToken)
	if r.Method == http.MethodPost && !strings.HasPrefix(r.URL.Path, "/training/") {
		r.Header.Set("X-SOC-Request", "1")
	}
	r.Host = g.backend.Host
	r = r.WithContext(context.WithValue(r.Context(), actorContextKey{}, actor))
	g.proxy.ServeHTTP(w, r)
}

func main() {
	listen := flag.String("listen", "127.0.0.1:9001", "gateway listen address")
	backend := flag.String("backend", "http://127.0.0.1:9000", "Python dashboard loopback URL")
	credentialsPath := flag.String("credentials", "", "JSON file of analyst usernames and salted PBKDF2 password hashes")
	cert := flag.String("tls-cert", "", "TLS certificate")
	key := flag.String("tls-key", "", "TLS private key")
	publicHost := flag.String("public-host", "", "expected public DNS hostname when TLS is enabled")
	flag.Parse()
	if *credentialsPath == "" {
		log.Fatal("--credentials is required")
	}
	secret := os.Getenv("SOC_INTERNAL_TOKEN")
	credentials, err := loadCredentials(*credentialsPath)
	if err != nil {
		log.Fatal(err)
	}
	secure := *cert != "" && *key != ""
	if !secure {
		host, _, err := net.SplitHostPort(*listen)
		if err != nil {
			log.Fatal(err)
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			log.Fatal("TLS is required for non-loopback listeners")
		}
	}
	if (*cert == "") != (*key == "") {
		log.Fatal("both TLS certificate and key are required")
	}
	if secure && *publicHost == "" {
		log.Fatal("--public-host is required with TLS")
	}
	g, err := newGateway(*backend, secret, credentials, secure)
	if err != nil {
		log.Fatal(err)
	}
	g.publicHost = *publicHost
	srv := &http.Server{Addr: *listen, Handler: g, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Printf("SOC gateway listening on %s, Python backend %s", *listen, *backend)
	if secure {
		err = srv.ListenAndServeTLS(*cert, *key)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
