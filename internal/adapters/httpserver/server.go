package httpserver

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/laibulle/robine-id/internal/application"
	"github.com/laibulle/robine-id/internal/domain"
	staticassets "github.com/laibulle/robine-id/priv/static"
)

type Server struct {
	Provider *application.Provider
	Logger   *slog.Logger
	codec    *sessionCodec
	views    renderer
	devMode  bool
}

type Options struct {
	SessionSecret string
	SecureCookies bool
	Development   bool
}

func New(provider *application.Provider, logger *slog.Logger, options Options) (*Server, error) {
	codec, err := newSessionCodec(options.SessionSecret, options.SecureCookies)
	if err != nil {
		return nil, err
	}
	return &Server{Provider: provider, Logger: logger, codec: codec, devMode: options.Development}, nil
}

func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(s.requestID, s.securityHeaders, s.recoverer)
	static, _ := fs.Sub(webFiles, "static")
	brand, _ := fs.Sub(staticassets.Files, "images/brand")
	router.Get("/assets/theme.css", s.themeCSS)
	router.Handle("/assets/brand/*", http.StripPrefix("/assets/brand/", http.FileServer(http.FS(brand))))
	router.Handle("/favicon.ico", http.FileServer(http.FS(staticassets.Files)))
	router.Handle("/assets/*", http.StripPrefix("/assets/", http.FileServer(http.FS(static))))
	router.Get("/", s.home)
	router.Get("/docs", s.docs)
	router.Get("/login", s.loginPage)
	router.Post("/login", s.login)
	router.Post("/logout", s.localLogout)
	router.Get("/account", s.accountPage)
	router.Post("/account", s.accountUpdate)
	router.Put("/account", s.accountUpdate)
	router.Get("/admin", s.adminUsers)
	router.Get("/admin/users", s.adminUsers)
	router.Get("/admin/users/{userID}/edit", s.adminEdit)
	router.Post("/admin/users/{userID}", s.adminUpdate)
	router.Put("/admin/users/{userID}", s.adminUpdate)
	router.Get("/health/live", s.live)
	router.Get("/health/ready", s.ready)
	router.Get("/{issuerID}/.well-known/openid-configuration", s.discovery)
	router.Get("/{issuerID}/jwks.json", s.jwks)
	router.Get("/{issuerID}/authorize", s.authorize)
	router.Post("/{issuerID}/authorize", s.authorize)
	router.Post("/{issuerID}/authorize/consent", s.consent)
	router.Post("/{issuerID}/token", s.token)
	router.Get("/{issuerID}/userinfo", s.userInfo)
	router.Post("/{issuerID}/userinfo", s.userInfo)
	router.Get("/{issuerID}/logout", s.logoutPage)
	router.Post("/{issuerID}/logout", s.logout)
	return router
}

type pageData struct {
	Title, ProductName, PrimaryColor, CSRF, Error, CorrelationID string
	Identifier, ClientName, IssuerID                             string
	Scopes                                                       []string
	Pending                                                      bool
	User                                                         domain.User
	Users                                                        []domain.User
	Roles                                                        string
	Enabled                                                      bool
}

func (s *Server) baseData(request *http.Request, session browserSession) pageData {
	data := pageData{Title: "Robine ID", ProductName: "Robine ID", PrimaryColor: "#176b70", CSRF: session.CSRF, CorrelationID: request.Header.Get("x-request-id")}
	if snapshot, err := s.Provider.Config.Active(request.Context()); err == nil {
		data.ProductName = snapshot.Branding.ProductName
		data.PrimaryColor = snapshot.Branding.PrimaryColor
	}
	return data
}

func isHTMX(request *http.Request) bool { return request.Header.Get("HX-Request") == "true" }

func (s *Server) render(writer http.ResponseWriter, request *http.Request, status int, page string, data pageData) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(status)
	if err := s.views.render(writer, page, isHTMX(request), data); err != nil {
		s.Logger.Error("render template", "error", err)
	}
}

func (s *Server) home(writer http.ResponseWriter, request *http.Request) {
	session := s.codec.read(request)
	_ = s.codec.write(writer, session)
	s.render(writer, request, 200, "home", s.baseData(request, session))
}
func (s *Server) docs(writer http.ResponseWriter, request *http.Request) {
	session := s.codec.read(request)
	_ = s.codec.write(writer, session)
	s.render(writer, request, 200, "docs", s.baseData(request, session))
}
func (s *Server) themeCSS(writer http.ResponseWriter, request *http.Request) {
	color := "#176b70"
	if snapshot, err := s.Provider.Config.Active(request.Context()); err == nil && snapshot.Branding.PrimaryColor != "" {
		color = snapshot.Branding.PrimaryColor
	}
	writer.Header().Set("Content-Type", "text/css; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-cache")
	_, _ = fmt.Fprintf(writer, ":root{--primary:%s;--auth-primary:%s}", color, color)
}
func (s *Server) live(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, 200, map[string]string{"status": "live"})
}
func (s *Server) ready(writer http.ResponseWriter, request *http.Request) {
	snapshot, err := s.Provider.Config.Active(request.Context())
	if err != nil {
		writeJSON(writer, 503, map[string]string{"status": "not_ready"})
		return
	}
	writeJSON(writer, 200, map[string]string{"status": "ready", "revision": snapshot.Fingerprint})
}
func (s *Server) discovery(writer http.ResponseWriter, request *http.Request) {
	metadata, err := s.Provider.Discovery(request.Context(), chi.URLParam(request, "issuerID"))
	if err != nil {
		writeProtocolJSON(writer, protocolError(err, "invalid_request"))
		return
	}
	writeJSON(writer, 200, metadata)
}
func (s *Server) jwks(writer http.ResponseWriter, request *http.Request) {
	keys, err := s.Provider.JWKS(request.Context(), chi.URLParam(request, "issuerID"))
	if err != nil {
		writeProtocolJSON(writer, protocolError(err, "invalid_request"))
		return
	}
	writeJSON(writer, 200, keys)
}

func (s *Server) loginPage(writer http.ResponseWriter, request *http.Request) {
	session := s.codec.read(request)
	_ = s.codec.write(writer, session)
	data := s.baseData(request, session)
	data.Title = "Sign in"
	s.render(writer, request, 200, "login", data)
}

func (s *Server) authorize(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		s.renderProtocolError(writer, request, protocol("invalid_request", "invalid form"))
		return
	}
	authorization, err := s.Provider.ValidateAuthorization(request.Context(), chi.URLParam(request, "issuerID"), request.Form)
	if err != nil {
		s.renderProtocolError(writer, request, err)
		return
	}
	session := s.codec.read(request)
	session.Pending = &authorization
	if session.SessionID != "" && !contains(authorization.Prompt, "login") {
		if _, err := s.Provider.ValidateSession(request.Context(), session.SessionID); err == nil {
			s.continueAuthorization(writer, request, &session)
			return
		}
		session.SessionID, session.Subject = "", ""
	}
	_ = s.codec.write(writer, session)
	data := s.baseData(request, session)
	data.Title = "Sign in"
	data.Pending = true
	s.render(writer, request, 200, "login", data)
}

func (s *Server) login(writer http.ResponseWriter, request *http.Request) {
	session := s.codec.read(request)
	if !s.validCSRF(request, session) {
		s.renderProtocolError(writer, request, protocol("invalid_request", "invalid CSRF token"))
		return
	}
	if err := request.ParseForm(); err != nil {
		s.renderProtocolError(writer, request, err)
		return
	}
	remote, _, _ := net.SplitHostPort(request.RemoteAddr)
	user, retry, err := s.Provider.Authenticate(request.Context(), request.Form.Get("identifier"), request.Form.Get("password"), remote)
	if err != nil {
		data := s.baseData(request, session)
		data.Title = "Sign in"
		data.Error = "The identifier or password is incorrect."
		data.Identifier = request.Form.Get("identifier")
		if retry > 0 {
			writer.Header().Set("Retry-After", strconv.Itoa(max(1, int(retry.Seconds()))))
			data.Error = "Too many attempts. Please try again shortly."
			s.render(writer, request, 429, "login", data)
			return
		}
		s.render(writer, request, 401, "login", data)
		return
	}
	registered, err := s.Provider.StartSession(request.Context(), user.ID)
	if err != nil {
		s.renderProtocolError(writer, request, err)
		return
	}
	session.SessionID, session.Subject, session.AuthTime = registered.ID, user.ID, registered.StartedAt
	if session.Pending != nil {
		s.continueAuthorization(writer, request, &session)
		return
	}
	destination := session.ReturnTo
	if destination == "" {
		destination = "/"
	}
	session.ReturnTo = ""
	_ = s.codec.write(writer, session)
	s.redirect(writer, request, destination)
}

func (s *Server) continueAuthorization(writer http.ResponseWriter, request *http.Request, session *browserSession) {
	snapshot, err := s.Provider.Config.Active(request.Context())
	if err != nil {
		s.renderProtocolError(writer, request, err)
		return
	}
	var client domain.Client
	for _, candidate := range snapshot.Clients {
		if candidate.ID == session.Pending.ClientID {
			client = candidate
			break
		}
	}
	if client.RequiresConsent() || contains(session.Pending.Prompt, "consent") {
		_ = s.codec.write(writer, *session)
		data := s.baseData(request, *session)
		data.Title = "Authorize access"
		data.ClientName = client.Name
		data.Scopes = session.Pending.Scopes
		data.IssuerID = session.Pending.IssuerID
		s.render(writer, request, 200, "consent", data)
		return
	}
	s.completeAuthorization(writer, request, session)
}

func (s *Server) consent(writer http.ResponseWriter, request *http.Request) {
	session := s.codec.read(request)
	if !s.validCSRF(request, session) || session.Pending == nil {
		s.renderProtocolError(writer, request, protocol("invalid_request", "authorization session is invalid"))
		return
	}
	if request.FormValue("decision") != "approve" {
		destination := callbackURL(session.Pending.RedirectURI, map[string]string{"error": "access_denied", "state": session.Pending.State})
		session.Pending = nil
		_ = s.codec.write(writer, session)
		s.redirect(writer, request, destination)
		return
	}
	s.completeAuthorization(writer, request, &session)
}

func (s *Server) completeAuthorization(writer http.ResponseWriter, request *http.Request, session *browserSession) {
	code, err := s.Provider.IssueAuthorizationCode(request.Context(), *session.Pending, session.Subject, session.AuthTime)
	if err != nil {
		s.renderProtocolError(writer, request, err)
		return
	}
	destination := callbackURL(session.Pending.RedirectURI, map[string]string{"code": code, "state": session.Pending.State})
	session.Pending = nil
	_ = s.codec.write(writer, *session)
	s.redirect(writer, request, destination)
}

func tokenCredentials(request *http.Request) (id, transport, secret string, ok bool) {
	if username, password, basic := request.BasicAuth(); basic {
		return username, "client_secret_basic", password, true
	}
	id = request.Form.Get("client_id")
	if value := request.Form.Get("client_secret"); value != "" {
		return id, "client_secret_post", value, true
	}
	return id, "none", "", id != ""
}

func (s *Server) token(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	if err := request.ParseForm(); err != nil {
		writeProtocolJSON(writer, protocolError(err, "invalid_request"))
		return
	}
	id, transport, secret, ok := tokenCredentials(request)
	if !ok {
		writeProtocolJSON(writer, protocolError(applicationClientError(), "invalid_client"))
		return
	}
	if request.Form.Get("client_id") == "" {
		request.Form.Set("client_id", id)
	} else if request.Form.Get("client_id") != id {
		writeProtocolJSON(writer, protocolError(applicationClientError(), "invalid_client"))
		return
	}
	client, err := s.Provider.AuthenticateClient(request.Context(), id, transport, secret)
	if err != nil {
		writer.Header().Set("WWW-Authenticate", `Basic realm="token"`)
		writeProtocolJSON(writer, protocolError(err, "invalid_client"))
		return
	}
	tokens, err := s.Provider.ExchangeCode(request.Context(), chi.URLParam(request, "issuerID"), request.Form, client)
	if err != nil {
		writeProtocolJSON(writer, protocolError(err, "invalid_grant"))
		return
	}
	writeJSON(writer, 200, map[string]any{"access_token": tokens.AccessToken, "id_token": tokens.IDToken, "token_type": tokens.TokenType, "expires_in": tokens.ExpiresIn, "scope": tokens.Scope})
}

func applicationClientError() error {
	return &domain.ProtocolError{Code: "invalid_client", Description: "client authentication failed", Status: 401}
}

func (s *Server) userInfo(writer http.ResponseWriter, request *http.Request) {
	header := request.Header.Get("Authorization")
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		invalidBearer(writer)
		return
	}
	info, err := s.Provider.UserInfo(request.Context(), chi.URLParam(request, "issuerID"), parts[1])
	if err != nil {
		invalidBearer(writer)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, 200, info)
}

func invalidBearer(writer http.ResponseWriter) {
	writer.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	writeJSON(writer, 401, map[string]string{"error": "invalid_token"})
}

func (s *Server) logoutPage(writer http.ResponseWriter, request *http.Request) {
	session := s.codec.read(request)
	redirectURI := request.URL.Query().Get("post_logout_redirect_uri")
	if redirectURI != "" {
		hint := request.URL.Query().Get("id_token_hint")
		if hint == "" {
			writeProtocolJSON(writer, protocolError(protocol("invalid_request", "id_token_hint is required when a post-logout redirect is requested"), "invalid_request"))
			return
		}
		claims, err := s.Provider.VerifyIDToken(request.Context(), chi.URLParam(request, "issuerID"), hint)
		if err != nil {
			writeProtocolJSON(writer, protocolError(protocol("invalid_request", "post_logout_redirect_uri is not registered for the token client"), "invalid_request"))
			return
		}
		audience, ok := claims["aud"].(string)
		if !ok {
			writeProtocolJSON(writer, protocolError(protocol("invalid_request", "post_logout_redirect_uri is not registered for the token client"), "invalid_request"))
			return
		}
		snapshot, err := s.Provider.Config.Active(request.Context())
		if err != nil {
			s.renderProtocolError(writer, request, err)
			return
		}
		trusted := false
		for _, client := range snapshot.Clients {
			if client.ID == audience && contains(client.PostLogoutRedirectURIs, redirectURI) {
				trusted = true
				break
			}
		}
		if !trusted {
			writeProtocolJSON(writer, protocolError(protocol("invalid_request", "post_logout_redirect_uri is not registered for the token client"), "invalid_request"))
			return
		}
		session.LogoutReturnTo = callbackURL(redirectURI, map[string]string{"state": request.URL.Query().Get("state")})
	} else {
		session.LogoutReturnTo = ""
	}
	_ = s.codec.write(writer, session)
	data := s.baseData(request, session)
	data.Title = "Sign out"
	data.IssuerID = chi.URLParam(request, "issuerID")
	s.render(writer, request, 200, "logout", data)
}
func (s *Server) logout(writer http.ResponseWriter, request *http.Request) {
	session := s.codec.read(request)
	if !s.validCSRF(request, session) {
		s.renderProtocolError(writer, request, protocol("invalid_request", "invalid CSRF token"))
		return
	}
	if session.SessionID != "" {
		_ = s.Provider.EndSession(request.Context(), session.SessionID)
	}
	returnTo := session.LogoutReturnTo
	s.codec.clear(writer)
	if returnTo != "" {
		s.redirect(writer, request, returnTo)
		return
	}
	s.render(writer, request, 200, "signed_out", s.baseData(request, s.codec.fresh()))
}
func (s *Server) localLogout(writer http.ResponseWriter, request *http.Request) {
	s.logout(writer, request)
}

func (s *Server) authenticatedUser(writer http.ResponseWriter, request *http.Request) (browserSession, domain.User, bool) {
	session := s.codec.read(request)
	if session.SessionID == "" {
		s.requireLogin(writer, request, session)
		return session, domain.User{}, false
	}
	if _, err := s.Provider.ValidateSession(request.Context(), session.SessionID); err != nil {
		session.SessionID, session.Subject = "", ""
		s.requireLogin(writer, request, session)
		return session, domain.User{}, false
	}
	user, err := s.Provider.UserByID(request.Context(), session.Subject)
	if err != nil || !user.IsEnabled() {
		session.SessionID, session.Subject = "", ""
		s.requireLogin(writer, request, session)
		return session, domain.User{}, false
	}
	return session, user, true
}

func (s *Server) requireLogin(writer http.ResponseWriter, request *http.Request, session browserSession) {
	session.ReturnTo = request.URL.Path
	_ = s.codec.write(writer, session)
	s.redirect(writer, request, "/login")
}

func (s *Server) accountPage(writer http.ResponseWriter, request *http.Request) {
	session, user, ok := s.authenticatedUser(writer, request)
	if !ok {
		return
	}
	data := s.baseData(request, session)
	data.Title = "Your account"
	data.User = user
	s.render(writer, request, 200, "account", data)
}

func (s *Server) accountUpdate(writer http.ResponseWriter, request *http.Request) {
	session, user, ok := s.authenticatedUser(writer, request)
	if !ok {
		return
	}
	if !s.validCSRF(request, session) {
		s.renderProtocolError(writer, request, protocol("invalid_request", "invalid CSRF token"))
		return
	}
	updated, err := s.Provider.UpdateProfile(request.Context(), user.ID, application.ProfileUpdate{Name: request.Form.Get("name"), Email: request.Form.Get("email"), CurrentPassword: request.Form.Get("current_password"), NewPassword: request.Form.Get("new_password"), PasswordConfirmation: request.Form.Get("password_confirmation")})
	if err != nil {
		data := s.baseData(request, session)
		data.Title = "Your account"
		data.User = user
		data.User.Name = request.Form.Get("name")
		data.User.Email = request.Form.Get("email")
		data.Error = validationMessage(err)
		s.render(writer, request, 422, "account", data)
		return
	}
	data := s.baseData(request, session)
	data.Title = "Your account"
	data.User = updated
	data.Error = "Your account has been updated."
	s.render(writer, request, 200, "account", data)
}

func (s *Server) requireAdmin(writer http.ResponseWriter, request *http.Request) (browserSession, domain.User, bool) {
	session, user, ok := s.authenticatedUser(writer, request)
	if !ok {
		return session, user, false
	}
	if !application.Admin(user) {
		http.Error(writer, "Forbidden", http.StatusForbidden)
		return session, user, false
	}
	return session, user, true
}

func (s *Server) adminUsers(writer http.ResponseWriter, request *http.Request) {
	session, _, ok := s.requireAdmin(writer, request)
	if !ok {
		return
	}
	users, err := s.Provider.ListUsers(request.Context())
	if err != nil {
		s.renderProtocolError(writer, request, err)
		return
	}
	data := s.baseData(request, session)
	data.Title = "User administration"
	data.Users = users
	s.render(writer, request, 200, "admin_users", data)
}

func (s *Server) adminEdit(writer http.ResponseWriter, request *http.Request) {
	session, _, ok := s.requireAdmin(writer, request)
	if !ok {
		return
	}
	user, err := s.Provider.UserByID(request.Context(), chi.URLParam(request, "userID"))
	if err != nil {
		http.NotFound(writer, request)
		return
	}
	data := s.baseData(request, session)
	data.Title = "Manage " + user.Name
	data.User = user
	data.Roles = strings.Join(user.Roles, ", ")
	data.Enabled = user.IsEnabled()
	s.render(writer, request, 200, "admin_edit", data)
}

func (s *Server) adminUpdate(writer http.ResponseWriter, request *http.Request) {
	session, actor, ok := s.requireAdmin(writer, request)
	if !ok {
		return
	}
	if !s.validCSRF(request, session) {
		s.renderProtocolError(writer, request, protocol("invalid_request", "invalid CSRF token"))
		return
	}
	enabled := request.Form.Get("enabled") == "true" || request.Form.Get("enabled") == "on"
	updated, err := s.Provider.UpdateUserAsAdmin(request.Context(), actor.ID, chi.URLParam(request, "userID"), application.AdminUpdate{Name: request.Form.Get("name"), Email: request.Form.Get("email"), Roles: request.Form.Get("roles"), Enabled: enabled})
	if err != nil {
		data := s.baseData(request, session)
		data.Title = "Manage user"
		data.User, _ = s.Provider.UserByID(request.Context(), chi.URLParam(request, "userID"))
		data.Roles = request.Form.Get("roles")
		data.Enabled = enabled
		data.Error = validationMessage(err)
		s.render(writer, request, 422, "admin_edit", data)
		return
	}
	data := s.baseData(request, session)
	data.Title = "Manage " + updated.Name
	data.User = updated
	data.Roles = strings.Join(updated.Roles, ", ")
	data.Enabled = updated.IsEnabled()
	data.Error = "The account has been updated."
	s.render(writer, request, 200, "admin_edit", data)
}

func validationMessage(err error) string {
	var validation domain.ValidationError
	if !errors.As(err, &validation) {
		return "Your changes could not be saved."
	}
	messages := make([]string, 0, len(validation))
	for field, message := range validation {
		messages = append(messages, strings.ReplaceAll(field, "_", " ")+" "+message)
	}
	slices.Sort(messages)
	return strings.Join(messages, ". ")
}

func (s *Server) validCSRF(request *http.Request, session browserSession) bool {
	_ = request.ParseForm()
	submitted := request.Form.Get("csrf_token")
	return len(submitted) == len(session.CSRF) && subtle.ConstantTimeCompare([]byte(submitted), []byte(session.CSRF)) == 1
}
func (s *Server) redirect(writer http.ResponseWriter, request *http.Request, destination string) {
	if isHTMX(request) {
		writer.Header().Set("HX-Redirect", destination)
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(writer, request, destination, http.StatusSeeOther)
}
func callbackURL(destination string, values map[string]string) string {
	parsed, _ := url.Parse(destination)
	query := parsed.Query()
	for key, value := range values {
		if value != "" {
			query.Set(key, value)
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}
func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
func protocol(code, description string) error { return domain.NewProtocolError(code, description) }

func protocolError(err error, fallback string) *domain.ProtocolError {
	var target *domain.ProtocolError
	if errors.As(err, &target) {
		return target
	}
	return &domain.ProtocolError{Code: fallback, Description: "request could not be completed", Status: 400}
}
func writeProtocolJSON(writer http.ResponseWriter, problem *domain.ProtocolError) {
	if problem.Status == 0 {
		problem.Status = 400
	}
	writeJSON(writer, problem.Status, map[string]string{"error": problem.Code, "error_description": problem.Description})
}
func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func (s *Server) renderProtocolError(writer http.ResponseWriter, request *http.Request, err error) {
	session := s.codec.read(request)
	data := s.baseData(request, session)
	problem := protocolError(err, "server_error")
	data.Title = "Request error"
	data.Error = problem.Description
	s.render(writer, request, problem.Status, "error", data)
}

func (s *Server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		id := request.Header.Get("x-request-id")
		if id == "" || len(id) > 128 {
			id, _ = randomString()
		}
		request.Header.Set("x-request-id", id)
		writer.Header().Set("x-request-id", id)
		next.ServeHTTP(writer, request)
	})
}
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Frame-Options", "DENY")
		contentSecurityPolicy := "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:"
		if s.devMode {
			// Air injects a small inline reload client and its build-error styles.
			contentSecurityPolicy = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; worker-src 'self'; connect-src 'self'"
		}
		writer.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		next.ServeHTTP(writer, request)
	})
}
func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.Logger.Error("request panic", "error", fmt.Sprint(recovered))
				writeJSON(writer, 500, map[string]string{"error": "server_error"})
			}
		}()
		next.ServeHTTP(writer, request)
	})
}
