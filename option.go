package apple

import "net/http"

// ClientSettings represents settings for creation of new client.
type ClientSettings struct {
	HTTPClient  *http.Client
	TokenTTL    *int64
	RedirectURI *string

	TeamID   string
	ClientID string
	KeyID    string
}

// ClientOption is an interface for applying client options.
type ClientOption interface {
	Apply(*ClientSettings)
}

// ClientOptionFunc implements ClientOption interface using func trick.
type ClientOptionFunc func(*ClientSettings)

// Apply applies changes for ClientSettings.
func (f ClientOptionFunc) Apply(settings *ClientSettings) { f(settings) }

// WithHTTPClient sets specified client to ClientOptions.
func WithHTTPClient(client *http.Client) ClientOption {
	return ClientOptionFunc(func(settings *ClientSettings) {
		settings.HTTPClient = client
	})
}

// WithTokenTTL sets specified ttl to ClientOptions.
func WithTokenTTL(ttl int64) ClientOption {
	return ClientOptionFunc(func(settings *ClientSettings) {
		settings.TokenTTL = &ttl
	})
}

// WithRedirectURI sets specified uri to ClientOptions.
func WithRedirectURI(uri string) ClientOption {
	return ClientOptionFunc(func(settings *ClientSettings) {
		settings.RedirectURI = &uri
	})
}

// WithCredentials sets specified creds to ClientOptions.
func WithCredentials(teamID, clientID, keyID string) ClientOption {
	return ClientOptionFunc(func(settings *ClientSettings) {
		settings.TeamID = teamID
		settings.ClientID = clientID
		settings.KeyID = keyID
	})
}
