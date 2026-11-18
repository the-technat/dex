package authflow

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/storage"
)

// TestIssueIDTokenOmitGroups checks that the authorization endpoint's ID token
// honors the client's OmitGroupsFromIDToken, unless it is the only token the
// response carries and groups would otherwise be lost.
func TestIssueIDTokenOmitGroups(t *testing.T) {
	_, ts := newTestHandler(t, nil)
	h := ts.Handler
	ctx := t.Context()

	require.NoError(t, h.Storage.CreateClient(ctx, storage.Client{ID: "omit", OmitGroupsFromIDToken: true}))
	require.NoError(t, h.Storage.CreateClient(ctx, storage.Client{ID: "keep"}))

	tests := []struct {
		name        string
		clientID    string
		accessToken string
		code        string
		wantGroups  bool
	}{
		{name: "id_token token omits groups", clientID: "omit", accessToken: "at", wantGroups: false},
		{name: "code id_token omits groups", clientID: "omit", code: "c", wantGroups: false},
		{name: "id_token alone keeps groups", clientID: "omit", wantGroups: true},
		{name: "client without the flag keeps groups", clientID: "keep", accessToken: "at", wantGroups: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			authReq := storage.AuthRequest{
				ClientID:      tc.clientID,
				ResponseTypes: []string{"id_token"},
				Scopes:        []string{"openid", "groups"},
				Claims:        storage.Claims{UserID: "u1", Groups: []string{"admins"}},
				ConnectorID:   "mock",
			}
			resp := &authResponse{accessToken: tc.accessToken, code: storage.AuthCode{ID: tc.code}}
			rr := httptest.NewRecorder()
			require.True(t, h.issueIDToken(ctx, rr, httptest.NewRequest("GET", "/", nil), authReq, resp), rr.Body.String())

			jws, err := jose.ParseSigned(resp.idToken, []jose.SignatureAlgorithm{jose.RS256})
			require.NoError(t, err)
			var claims struct {
				Groups []string `json:"groups"`
			}
			require.NoError(t, json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &claims))
			if tc.wantGroups {
				require.Equal(t, []string{"admins"}, claims.Groups)
			} else {
				require.Empty(t, claims.Groups)
			}
		})
	}
}
