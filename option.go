package apple

import "net/http"

type ClientSettings struct {
	HTTPClient  *http.Client
	TokenTTL    int64
	RedirectURI string

	TeamID   string
	ClientID string
	KeyID    string
}

type ClientOption interface {
	Apply(*ClientSettings)
}

type ClientOptionFunc func(*ClientSettings)

func (f ClientOptionFunc) Apply(settings *ClientSettings) { f(settings) }

func WithHTTPClient(client *http.Client) ClientOption {
	return ClientOptionFunc(func(settings *ClientSettings) {
		settings.HTTPClient = client
	})
}

func WithTokenTTL(ttl int64) ClientOption {
	return ClientOptionFunc(func(settings *ClientSettings) {
		settings.TokenTTL = ttl
	})
}

func WithRedirectURI(uri string) ClientOption {
	return ClientOptionFunc(func(settings *ClientSettings) {
		settings.RedirectURI = uri
	})
}

func WithCredentials(teamID, clientID, keyID string) ClientOption {
	return ClientOptionFunc(func(settings *ClientSettings) {
		settings.TeamID = teamID
		settings.ClientID = clientID
		settings.KeyID = keyID
	})
}
