package apple

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	KEYS = `{
		"keys": [
		  {
			"kty": "RSA",
			"kid": "86D88Kf",
			"use": "sig",
			"alg": "RS256",
			"n": "iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ",
			"e": "AQAB"
		  },
		  {
			"kty": "RSA",
			"kid": "eXaunmL",
			"use": "sig",
			"alg": "RS256",
			"n": "4dGQ7bQK8LgILOdLsYzfZjkEAoQeVC_aqyc8GC6RX7dq_KvRAQAWPvkam8VQv4GK5T4ogklEKEvj5ISBamdDNq1n52TpxQwI2EqxSk7I9fKPKhRt4F8-2yETlYvye-2s6NeWJim0KBtOVrk0gWvEDgd6WOqJl_yt5WBISvILNyVg1qAAM8JeX6dRPosahRVDjA52G2X-Tip84wqwyRpUlq2ybzcLh3zyhCitBOebiRWDQfG26EH9lTlJhll-p_Dg8vAXxJLIJ4SNLcqgFeZe4OfHLgdzMvxXZJnPp_VgmkcpUdRotazKZumj6dBPcXI_XID4Z4Z3OM1KrZPJNdUhxw",
			"e": "AQAB"
		  }
		]
	  }`

	CERT = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg+94fs23vSrhBIXNz
OdeRb7+FJkIsVrnTSf7eIYKdf4mgCgYIKoZIzj0DAQehRANCAATyBS3eRgOJ53OQ
LFhGSJw4aiqju7muVwoIWFxCcFJasRwyGcbs0C7vt3xKV/DRJvID4UljaI53wETq
RxlkNCeV
-----END PRIVATE KEY-----`

	BADCERT = `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCjcGqTkOq0CR3rTx0ZSQSIdTrDrFAYl29611xN8aVgMQIWtDB/
lD0W5TpKPuU9iaiG/sSn/VYt6EzN7Sr332jj7cyl2WrrHI6ujRswNy4HojMuqtfa
b5FFDpRmCuvl35fge18OvoQTJELhhJ1EvJ5KUeZiuJ3u3YyMnxxXzLuKbQIDAQAB
AoGAPrNDz7TKtaLBvaIuMaMXgBopHyQd3jFKbT/tg2Fu5kYm3PrnmCoQfZYXFKCo
ZUFIS/G1FBVWWGpD/MQ9tbYZkKpwuH+t2rGndMnLXiTC296/s9uix7gsjnT4Naci
5N6EN9pVUBwQmGrYUTHFc58ThtelSiPARX7LSU2ibtJSv8ECQQDWBRrrAYmbCUN7
ra0DFT6SppaDtvvuKtb+mUeKbg0B8U4y4wCIK5GH8EyQSwUWcXnNBO05rlUPbifs
DLv/u82lAkEAw39sTJ0KmJJyaChqvqAJ8guulKlgucQJ0Et9ppZyet9iVwNKX/aW
9UlwGBMQdafQ36nd1QMEA8AbAw4D+hw/KQJBANJbHDUGQtk2hrSmZNoV5HXB9Uiq
7v4N71k5ER8XwgM5yVGs2tX8dMM3RhnBEtQXXs9LW1uJZSOQcv7JGXNnhN0CQBZe
nzrJAWxh3XtznHtBfsHWelyCYRIAj4rpCHCmaGUM6IjCVKFUawOYKp5mmAyObkUZ
f8ue87emJLEdynC1CLkCQHduNjP1hemAGWrd6v8BHhE3kKtcK6KHsPvJR5dOfzbd
HAqVePERhISfN6cwZt5p8B3/JUwSR8el66DF7Jm57BM=
-----END RSA PRIVATE KEY-----`

	goodSignatureString = `eyJhbGciOiJFUzI1NiIsImtpZCI6ImlkaWRpZGlkIn0.eyJhdWQiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiZXhwIjoxNTk2ODAwODcwLCJpYXQiOjE1OTY3OTcyNzAsImlzcyI6IjEyMzQ1Njc4OTAiLCJzdWIiOiJjb20uZXhhbXBsZS5hcHAifQ.fuCSrxP5NzkgLM-zjEnUkKn4b_YR0Tbc7_j6MmCor5O9UsM6vpSa51h0SdbXH-l5RYJmGoiVVY6hyug3t5ZPwA`
)

func TestLoadCertGetSignature(t *testing.T) {
	tests := []struct {
		name        string
		cert        string
		signature   string
		wantLoadErr bool
		forceLoad   bool // to check fail at next stage
		wantErr     bool
	}{
		{
			name:        "bad key",
			cert:        "bad_key",
			wantLoadErr: true,
			wantErr:     true,
		},
		{
			name:        "bad key wrong format fail load",
			cert:        BADCERT,
			wantLoadErr: true,
			forceLoad:   false,
		},
		{
			name:        "bad key wrong format force load",
			cert:        BADCERT,
			wantLoadErr: true,
			forceLoad:   true,
			wantErr:     true,
		},
		{
			name:        "good key",
			cert:        CERT,
			wantLoadErr: false,
			wantErr:     false,
		},
	}

	srv := setupMockServer(t, "", nil)
	c, err := NewClient(
		WithBaseURL(srv.URL),
		WithCredentials("1234567890", "com.example.app", "idididid"),
	)
	require.NoError(t, err)

	var publicKey crypto.PublicKey

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err = c.LoadP8CertByByte([]byte(tt.cert))
			if tt.wantLoadErr {
				assert.Error(t, err)
				if !tt.forceLoad {
					return
				}
			} else {
				require.NoError(t, err)

				publicKey = (c.AESCert.(*ecdsa.PrivateKey)).Public()
			}

			got, err := c.getSignature()

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err, "expected no error but got %s", err)
			require.NotEmpty(t, got, "wanted a secret string returned but got none")

			token, err := jwt.ParseWithClaims(
				got,
				&jwt.StandardClaims{},
				func(token *jwt.Token) (interface{}, error) {
					return publicKey, nil
				})

			require.NoError(t, err, "error while decoding JWT")
			require.True(t, token.Valid)

			claims, ok := token.Claims.(*jwt.StandardClaims)
			assert.True(t, ok)

			assert.Equal(t, "1234567890", claims.Issuer)
			assert.Equal(t, "com.example.app", claims.Subject)
			assert.Equal(t, "https://appleid.apple.com", claims.Audience)
			assert.Equal(t, c.TokenTTL, claims.ExpiresAt-claims.IssuedAt)
		})
	}
}

// many cases require initial Public Keys response during creating Client or later
func setupMockServer(t *testing.T, expectedRequest string, responseToken *TokenResponse) *httptest.Server {
	handler := http.NewServeMux()

	handler.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(KEYS))
	})

	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s, err := ioutil.ReadAll(r.Body)
		assert.NoError(t, err)

		if expectedRequest != "" {
			assert.Equal(t, expectedRequest, string(s))
		}

		b, _ := json.Marshal(responseToken)
		w.Write(b)
	})

	srv := httptest.NewServer(handler)

	return srv
}
