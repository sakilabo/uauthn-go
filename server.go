package uauthn

import (
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

//go:embed index.html
var defaultIndex []byte

const (
	CookieName = "uauthn"
	UserHeader = "Remote-User"
	cookieAge  = 400 * 24 * time.Hour
)

type Logf func(format string, args ...any)

type Options struct {
	Prefix        string
	Domain        string
	Expire        time.Duration
	Index         string
	PasskeyPrompt string
	Users         *Users
	Sessions      *Sessions
	Logf          Logf
	// TrustForwarded takes the scheme and host from X-Forwarded-Proto/Host (standalone behind a proxy).
	TrustForwarded bool
}

type Server struct {
	opt        Options
	challenges challenges
}

func NewServer(opt Options) *Server {
	if opt.PasskeyPrompt == "" {
		opt.PasskeyPrompt = PromptAlways
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	return &Server{opt: opt}
}

func (s *Server) Prefix() string { return s.opt.Prefix }

func (s *Server) StripPrefix(p string) (string, bool) {
	rest, ok := strings.CutPrefix(p, s.opt.Prefix)
	if !ok || (rest != "" && rest[0] != '/') {
		return "", false
	}
	return rest, true
}

func (s *Server) Handle(w http.ResponseWriter, r *http.Request, path string) {
	switch path {
	case "":
		http.Redirect(w, r, s.opt.Prefix+"/", http.StatusFound)
	case "/", "/index.html":
		s.serveIndex(w, r)
	case "/challenge":
		s.serveChallenge(w, r)
	case "/login":
		s.serveLogin(w, r)
	case "/passkey":
		s.servePasskey(w, r)
	case "/logout":
		s.serveLogout(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) Authenticate(r *http.Request) (string, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return "", false
	}
	user, key, ok := ParseSessionValue(c.Value)
	if !ok || !s.opt.Users.Exists(user) {
		return "", false
	}
	return user, s.opt.Sessions.Check(user, key, s.opt.Expire)
}

// A 401 whose body redirects to the login page works with Caddy and Traefik as is, and with nginx via error_page.
func (s *Server) Unauthorized(w http.ResponseWriter, r *http.Request, original string) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	target := html.EscapeString(s.opt.Prefix + "/?rd=" + url.QueryEscape(original))
	h.Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	io.WriteString(w, `<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=`+target+
		`"><title>Sign in</title><a href="`+target+`">Sign in</a>`)
}

func (s *Server) origin(r *http.Request) (scheme, host string) {
	scheme, host = "http", r.Host
	if r.TLS != nil {
		scheme = "https"
	}
	if s.opt.TrustForwarded {
		if v := firstValue(r.Header.Get("X-Forwarded-Proto")); v != "" {
			scheme = v
		}
		if v := firstValue(r.Header.Get("X-Forwarded-Host")); v != "" {
			host = v
		}
	}
	return scheme, host
}

func firstValue(v string) string {
	v, _, _ = strings.Cut(v, ",")
	return strings.TrimSpace(v)
}

func (s *Server) rpID(r *http.Request) string {
	if s.opt.Domain != "" {
		return s.opt.Domain
	}
	_, host := s.origin(r)
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func (s *Server) expectedOrigin(r *http.Request) string {
	scheme, host := s.origin(r)
	return scheme + "://" + host
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	data := defaultIndex
	if s.opt.Index != "" {
		if b, err := os.ReadFile(s.opt.Index); err == nil {
			data = b
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(data)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func userID(name string) string {
	h := sha256.Sum256([]byte(name))
	return b64url.EncodeToString(h[:])
}

func (s *Server) serveChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	user, ok := s.Authenticate(r)
	ch, err := s.challenges.issue(ok, user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	res := map[string]any{"challenge": ch, "rpId": s.rpID(r), "passkeyPrompt": s.opt.PasskeyPrompt}
	if ok {
		exclude := []string{}
		for _, pk := range s.opt.Users.Passkeys(user) {
			exclude = append(exclude, b64url.EncodeToString(pk.ID))
		}
		res["user"] = user
		res["userId"] = userID(user)
		res["exclude"] = exclude
	}
	writeJSON(w, http.StatusOK, res)
}

type loginRequest struct {
	Type              string `json:"type"`
	Username          string `json:"username"`
	Password          string `json:"password"`
	ID                string `json:"id"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	PublicKey         string `json:"publicKey"`
	Alg               int    `json:"alg"`
}

func decodeRequest(w http.ResponseWriter, r *http.Request) (*loginRequest, bool) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return nil, false
	}
	var req loginRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return nil, false
	}
	return &req, true
}

func decodeFields(vals ...string) ([][]byte, error) {
	out := make([][]byte, len(vals))
	for i, v := range vals {
		b, err := b64url.DecodeString(v)
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}

func (s *Server) serveLogin(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeRequest(w, r)
	if !ok {
		return
	}
	var user string
	var err error
	switch req.Type {
	case "password":
		user = req.Username
		if !s.opt.Users.VerifyPassword(user, req.Password) {
			err = errors.New("wrong user name or password")
		}
	case "passkey":
		user, err = s.verifyPasskeyLogin(r, req)
	default:
		err = errors.New("unknown login type")
	}
	if err != nil {
		s.opt.Logf("login failed: type=%s user=%q remote=%s: %v", req.Type, user, r.RemoteAddr, err)
		writeError(w, http.StatusUnauthorized, "sign-in failed")
		return
	}
	value, err := s.opt.Sessions.Create(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.setCookie(w, r, value, cookieAge)
	s.opt.Logf("login: type=%s user=%q remote=%s", req.Type, user, r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]string{"user": user})
}

func (s *Server) verifyPasskeyLogin(r *http.Request, req *loginRequest) (string, error) {
	f, err := decodeFields(req.ID, req.ClientDataJSON, req.AuthenticatorData, req.Signature)
	if err != nil {
		return "", errors.New("malformed passkey response")
	}
	id, cdj, ad, sig := f[0], f[1], f[2], f[3]
	user, pk, ok := s.opt.Users.FindPasskey(id)
	if !ok {
		return "", errors.New("unknown passkey")
	}
	cd, err := parseClientData(cdj, "webauthn.get", s.expectedOrigin(r))
	if err != nil {
		return user, err
	}
	if _, ok := s.challenges.take(cd.Challenge, false); !ok {
		return user, errors.New("unknown or expired challenge")
	}
	if err := checkAuthenticatorData(ad, s.rpID(r)); err != nil {
		return user, err
	}
	return user, verifyAssertion(pk, ad, cdj, sig)
}

func (s *Server) servePasskey(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeRequest(w, r)
	if !ok {
		return
	}
	user, ok := s.Authenticate(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "not signed in")
		return
	}
	pk, err := s.verifyRegistration(r, req, user)
	if err == nil {
		err = s.opt.Users.AddPasskey(user, pk)
	}
	if err != nil {
		s.opt.Logf("passkey registration failed: user=%q remote=%s: %v", user, r.RemoteAddr, err)
		writeError(w, http.StatusBadRequest, "registration failed")
		return
	}
	s.opt.Logf("passkey registered: user=%q remote=%s", user, r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]string{"user": user})
}

func (s *Server) verifyRegistration(r *http.Request, req *loginRequest, user string) (Passkey, error) {
	f, err := decodeFields(req.ID, req.ClientDataJSON, req.AuthenticatorData, req.PublicKey)
	if err != nil || len(f[0]) == 0 {
		return Passkey{}, errors.New("malformed registration response")
	}
	pk := Passkey{ID: f[0], Alg: req.Alg, Key: f[3]}
	cd, err := parseClientData(f[1], "webauthn.create", s.expectedOrigin(r))
	if err != nil {
		return pk, err
	}
	if u, ok := s.challenges.take(cd.Challenge, true); !ok || u != user {
		return pk, errors.New("unknown or expired challenge")
	}
	if err := checkAuthenticatorData(f[2], s.rpID(r)); err != nil {
		return pk, err
	}
	if _, err := parsePublicKey(pk.Alg, pk.Key); err != nil {
		return pk, err
	}
	if _, _, dup := s.opt.Users.FindPasskey(pk.ID); dup {
		return pk, errors.New("passkey already registered")
	}
	return pk, nil
}

func (s *Server) serveLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil {
		if user, key, ok := ParseSessionValue(c.Value); ok {
			s.opt.Sessions.Delete(user, key)
			s.opt.Logf("logout: user=%q remote=%s", user, r.RemoteAddr)
		}
	}
	s.setCookie(w, r, "", -1)
	target := "./"
	if rd := r.URL.Query().Get("rd"); isLocalPath(rd) {
		target = rd
	}
	// http.Redirect would resolve "./" against the path the proxy already stripped of the prefix.
	w.Header().Set("Location", target)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusFound)
}

func isLocalPath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "/\\")
}

func (s *Server) setCookie(w http.ResponseWriter, r *http.Request, value string, age time.Duration) {
	scheme, _ := s.origin(r)
	c := &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		Domain:   s.opt.Domain,
		HttpOnly: true,
		Secure:   scheme == "https",
		SameSite: http.SameSiteLaxMode,
	}
	if age < 0 {
		c.MaxAge = -1
	} else {
		c.MaxAge = int(age / time.Second)
	}
	http.SetCookie(w, c)
}
