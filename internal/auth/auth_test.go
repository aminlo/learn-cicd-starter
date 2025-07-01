package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		authHeader string
		wantKey    string
		wantErr    string
	}{
		"valid header": {
			authHeader: "ApiKey abc123",
			wantKey:    "abc123",
			wantErr:    "s",
		},
		"missing header": {
			authHeader: "",
			wantKey:    "",
			wantErr:    "no authorization header included",
		},
		"wrong prefix": {
			authHeader: "Bearer abc123",
			wantKey:    "",
			wantErr:    "malformed authorization header",
		},
		"only prefix": {
			authHeader: "ApiKey",
			wantKey:    "",
			wantErr:    "malformed authorization header",
		},
		"case sensitive prefix": {
			authHeader: "apikey abc123",
			wantKey:    "",
			wantErr:    "malformed authorization header",
		},
		"multiple spaces": {
			authHeader: "ApiKey abc123 def456",
			wantKey:    "abc123",
			wantErr:    "",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			headers := http.Header{}
			if tc.authHeader != "" {
				headers.Set("Authorization", tc.authHeader)
			}

			got, err := GetAPIKey(headers)

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error: %v, got nil", tc.wantErr)
				}
				if err.Error() != tc.wantErr {
					t.Fatalf("expected error: %v, got: %v", tc.wantErr, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
			}

			if got != tc.wantKey {
				t.Fatalf("expected key: %v, got: %v", tc.wantKey, got)
			}
		})
	}
}
