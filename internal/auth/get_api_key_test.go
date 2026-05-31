package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError string
	}{
		{
			name: "Valid API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			expectedKey:   "my-secret-key",
			expectedError: "",
		},
		{
			name:          "No Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name: "Malformed Authorization Header (No Prefix)",
			headers: http.Header{
				"Authorization": []string{"my-secret-key"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "Malformed Authorization Header (Wrong Prefix)",
			headers: http.Header{
				"Authorization": []string{"Bearer my-secret-key"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)
			if tt.expectedError != "" {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.expectedError)
					return
				}
				if err.Error() != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if key != tt.expectedKey {
				t.Errorf("expected key %v, got %v", tt.expectedKey, key)
			}
		})
	}
}
