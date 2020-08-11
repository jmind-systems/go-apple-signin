package apple

// Sign in with Apple REST API.
// Communicate between your app servers and Apple’s authentication servers.
// https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	defaultRequestTimeout = time.Second * 10
	defaultTokenTTL       = time.Hour

	defaultBaseURL = "https://appleid.apple.com/auth"
)

// Client for interaction with apple-id service.
type Client struct {
	TeamID      string      // Your Apple Team ID.
	ClientID    string      // Your Service which enable sign-in-with-apple service.
	KeyID       string      // Your Secret Key ID.
	AESCert     interface{} // Your Secret Key Created By X509 package.
	RedirectURI string      // Your RedirectURI config in apple website.
	TokenTTL    int64
	BaseURL     string

	hc         *http.Client
	publicKeys map[string]*rsa.PublicKey
}

// NewClient returns new client for interaction with apple-id service.
func NewClient(opts ...ClientOption) (*Client, error) {
	var settings ClientSettings
	for _, opt := range opts {
		opt.Apply(&settings)
	}

	client := Client{
		TeamID:   settings.TeamID,
		ClientID: settings.ClientID,
		KeyID:    settings.KeyID,
	}

	if settings.HTTPClient != nil {
		client.hc = settings.HTTPClient
	} else {
		client.hc = &http.Client{
			Transport: &http.Transport{},
			Timeout:   defaultRequestTimeout,
		}
	}

	if settings.TokenTTL != nil {
		client.TokenTTL = *settings.TokenTTL
	} else {
		client.TokenTTL = int64(defaultTokenTTL.Seconds())
	}

	if settings.RedirectURI != nil {
		client.RedirectURI = *settings.RedirectURI
	}

	if settings.BaseURL != nil {
		client.BaseURL = *settings.BaseURL
	} else {
		client.BaseURL = defaultBaseURL
	}

	jwkSet, err := client.FetchPublicKeys()
	if err != nil {
		return nil, err
	}

	client.publicKeys = make(map[string]*rsa.PublicKey)
	for _, k := range jwkSet.Keys {
		pubKey, err := NewPublicKey(k)
		if err != nil {
			return nil, err
		}

		client.publicKeys[k.KeyID] = pubKey
	}

	return &client, nil
}

// FetchPublicKeys to verify the ID token signature.
// https://developer.apple.com/documentation/sign_in_with_apple/fetch_apple_s_public_key_for_verifying_token_signature
func (c *Client) FetchPublicKeys() (*JWKSet, error) {
	resp, err := c.hc.Get(c.BaseURL + "/keys")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, ErrFetchPublicKey
	}

	jwkSet := JWKSet{}
	if err := json.NewDecoder(resp.Body).Decode(&jwkSet); err != nil {
		return nil, err
	}

	return &jwkSet, nil
}

// LoadP8CertByByte use x509.ParsePKCS8PrivateKey to Parse cert file.
func (c *Client) LoadP8CertByByte(data []byte) error {
	block, _ := pem.Decode(data)
	if block == nil {
		return ErrBadCert
	}
	cert, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadCert, err)
	}

	c.AESCert = cert

	return nil
}

// LoadP8CertByFile load file and parse it.
func (c *Client) LoadP8CertByFile(path string) error {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	return c.LoadP8CertByByte(b)
}

// CreateCallbackURL returns a callback URL for frontend.
// state: session ID of the user that Apple will return when
//        redirect_uri is called so that we can verify the sender.
func (c *Client) CreateCallbackURL(state string) string {
	u := url.Values{}
	u.Add("response_type", "code")
	u.Add("redirect_uri", c.RedirectURI)
	u.Add("client_id", c.ClientID)
	u.Add("state", state)
	u.Add("scope", "name email")

	return c.BaseURL + "/authorize?" + u.Encode()
}

// Authenticate with auth token.
// Documentation:
//   Response: https://developer.apple.com/documentation/sign_in_with_apple/tokenresponse
//   Error: https://developer.apple.com/documentation/sign_in_with_apple/errorresponse
func (c *Client) Authenticate(ctx context.Context, authCode string) (*TokenResponse, error) {
	signature, err := c.getSignature()
	if err != nil {
		return nil, err
	}

	v := url.Values{}
	v.Set("client_id", c.ClientID)
	v.Set("client_secret", signature)
	v.Set("grant_type", "authorization_code")
	v.Set("code", authCode)
	v.Set("redirect_uri", c.RedirectURI)

	token, err := c.doRequest(ctx, v)
	if err != nil {
		return nil, err
	}

	if err := c.ValidateToken(token.IDToken); err != nil {
		return nil, err
	}

	userIdentity, err := c.ParseUserIdentity(token.IDToken)
	if err != nil {
		return nil, err
	}

	token.UserIdentity = *userIdentity

	return token, nil
}

// Refresh access token.
// Documentation:
//   Response: https://developer.apple.com/documentation/sign_in_with_apple/tokenresponse
//   Error: https://developer.apple.com/documentation/sign_in_with_apple/errorresponse
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	signature, err := c.getSignature()
	if err != nil {
		return nil, err
	}

	v := url.Values{}
	v.Set("client_id", c.ClientID)
	v.Set("client_secret", signature)
	v.Set("grant_type", "refresh_token")
	v.Set("refresh_token", refreshToken)

	return c.doRequest(ctx, v)
}

func (c *Client) ParseUserIdentity(t string) (*UserIdentity, error) {
	parts := strings.Split(t, ".")
	if len(parts) < 2 {
		return nil, errors.New("invalid token")
	}

	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	userIdentity := UserIdentity{}
	if err := json.Unmarshal(body, &userIdentity); err != nil {
		return nil, err
	}

	return &userIdentity, nil
}

func (c *Client) ValidateToken(t string) error {
	if c.publicKeys == nil {
		_, err := c.FetchPublicKeys()
		return err
	}

	token, err := jwt.Parse(t, c.keyFunc)
	if err != nil {
		return err
	}

	if !token.Valid {
		return ErrInvalidToken
	}

	return nil
}

func (c *Client) doRequest(ctx context.Context, v url.Values) (*TokenResponse, error) {
	body := strings.NewReader(v.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/token", body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		errResponse := ErrorResponse{}
		if err := json.NewDecoder(resp.Body).Decode(&errResponse); err != nil {
			return nil, err
		}

		return nil, errResponse
	}

	t := TokenResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return nil, err
	}

	return &t, nil
}

func (c *Client) getSignature() (string, error) {
	if c.AESCert == nil {
		return "", ErrMissingCert
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.StandardClaims{
		Issuer:    c.TeamID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Unix() + c.TokenTTL,
		Audience:  "https://appleid.apple.com",
		Subject:   c.ClientID,
	})

	token.Header = map[string]interface{}{
		"kid": c.KeyID,
		"alg": "ES256",
	}

	return token.SignedString(c.AESCert)
}

func (c *Client) keyFunc(t *jwt.Token) (interface{}, error) {
	rawKid, ok := t.Header["kid"]
	if !ok {
		return nil, errors.New("jwt: kid not found")
	}

	kid, ok := rawKid.(string)
	if !ok {
		return nil, errors.New("jwt: wrong kid")
	}

	publicKey, ok := c.publicKeys[kid]
	if !ok {
		return nil, fmt.Errorf("unknown public key id: %s", kid)
	}

	return publicKey, nil
}
