package apple

import (
	"errors"
	"fmt"
)

var (
	// ErrMissingCert returned, if certificate is missing.
	ErrMissingCert = errors.New("cert for client not set")

	// ErrFetchPublicKey returned, if client failed fetching public key.
	ErrFetchPublicKey = errors.New("can't fetch apple public key")

	// ErrInvalidToken returned, if token is not valid.
	ErrInvalidToken = errors.New("invalid token")

	// ErrRemoveUnavailable returned, if remove server is not available.
	ErrRemoveUnavailable = errors.New("remove is not available")
)

// ErrorResponse is error object returned after an unsuccessful request.
type ErrorResponse struct {
	// A string that describes the reason for the unsuccessful request.
	// The string consists of a single allowed value.
	Err string `json:"error"`
}

func (e ErrorResponse) Error() string {
	switch e.Err {
	case "invalid_request":
		return "apple: invalid request"
	case "invalid_client":
		return "apple: client authentication failed"
	case "invalid_grant":
		return "apple: authorization grant or refresh token is invalid"
	case "unauthorized_client":
		return "apple: client is not authorized to use this authorization grant type"
	case "unsupported_grant_type":
		return "apple: authenticated client is not authorized to use the grant type"
	case "invalid_scope":
		return "apple: requested scope is invalid"
	default:
		return fmt.Sprintf("apple: unexpected error: %s", e.Err)
	}
}
