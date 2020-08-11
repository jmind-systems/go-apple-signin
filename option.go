package apple

import "net/http"

type ClientSettings struct {
	HTTPClient  *http.Client
	TokenTTL    int64
	RedirectURI string
	BaseURL     string

	TeamID   string // Your Apple Team ID obtained from Apple Developer Account.
	ClientID string // Your Service which enable sign-in-with-apple service.
	KeyID    string // Your Secret Key ID obtained from Apple Developer Account.
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

func WithBaseURL(url string) ClientOption {
	return ClientOptionFunc(func(settings *ClientSettings) {
		settings.BaseURL = url
	})
}
