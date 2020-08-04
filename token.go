package apple

// UserIdentity represents parsed user entity returned by apple.
type UserIdentity struct {
	// The unique identifier for the user.
	ID string `json:"sub"`

	// The user's email address.
	Email string `json:"email"`

	// A Boolean value that indicates whether the service has verified the email.
	// The value of this claim is always true because the servers only return verified email addresses.
	EmailVerified bool `json:"email_verified,string"`

	// The expiry time for the token. This value is typically set to five minutes.
	ExpiresAt int64 `json:"exp"`

	// The time the token was issued.
	IssuedAt int64 `json:"iat"`

	// A String value used to associate a client session and an ID token. This value is used to
	// mitigate replay attacks and is present only if passed during the authorization request.
	Nonce int64 `json:"nonce"`

	// A Boolean value that indicates whether the transaction is on a nonce-supported platform.
	// If you sent a nonce in the authorization request but do not see the nonce claim in the
	// ID token, check this claim to determine how to proceed. If this claim returns true you
	// should treat nonce as mandatory and fail the transaction; otherwise, you can proceed
	// treating the nonce as optional.
	NonceSupported bool `json:"nonce_supported"`
}

// TokenResponse represents the object returned on a successful request.
// https://developer.apple.com/documentation/sign_in_with_apple/tokenresponse
type TokenResponse struct {
	// (Reserved for future use) A token used to access allowed data.
	// Currently, no data set has been defined for access.
	AccessToken string `json:"access_token"`

	// The amount of time, in seconds, before the access token expires.
	ExpiresIn int64 `json:"expires_in"`

	// A JSON Web Token that contains the user’s identity information.
	IDToken      string       `json:"id_token"`
	UserIdentity UserIdentity `json:"-"` // Parsed IDToken.

	// The refresh token used to regenerate new access tokens.
	// Store this token securely on your server.
	RefreshToken string `json:"refresh_token"`

	// The type of access token. It will always be `bearer`.
	TokenType string `json:"token_type"`
}
