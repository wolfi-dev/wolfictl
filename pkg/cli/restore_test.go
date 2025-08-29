package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakePatchRequest(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse func(w http.ResponseWriter, r *http.Request)
		authToken      string
		expectError    bool
		errorContains  string
	}{
		{
			name: "successful PATCH request",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				// Verify request method
				assert.Equal(t, "PATCH", r.Method)

				// Verify authentication
				username, password, ok := r.BasicAuth()
				assert.True(t, ok)
				assert.Equal(t, "user", username)
				assert.Equal(t, "test-token", password)

				// Verify no body content for PATCH
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				assert.Empty(t, body)

				w.WriteHeader(http.StatusOK)
			},
			authToken:   "test-token",
			expectError: false,
		},
		{
			name: "server returns 404",
			serverResponse: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("Package not found"))
			},
			authToken:     "test-token",
			expectError:   true,
			errorContains: "PATCH request failed with status 404: Package not found",
		},
		{
			name: "server returns 500",
			serverResponse: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("Internal server error"))
			},
			authToken:     "test-token",
			expectError:   true,
			errorContains: "PATCH request failed with status 500: Internal server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(tt.serverResponse))
			defer server.Close()

			// Test the makePatchRequest function
			ctx := context.Background()
			err := makePatchRequest(ctx, server.URL, tt.authToken)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestMakePostRequest(t *testing.T) {
	tests := []struct {
		name           string
		packages       []string
		serverResponse func(w http.ResponseWriter, r *http.Request)
		authToken      string
		expectError    bool
		errorContains  string
	}{
		{
			name:     "successful POST request",
			packages: []string{"pkg1-1.0.0-r1", "pkg2-2.0.0-r2"},
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				// Verify request method
				assert.Equal(t, "POST", r.Method)

				// Verify authentication
				username, password, ok := r.BasicAuth()
				assert.True(t, ok)
				assert.Equal(t, "user", username)
				assert.Equal(t, "test-token", password)

				// Verify content type
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

				// Verify request body
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)

				var request BulkRestoreRequest
				err = json.Unmarshal(body, &request)
				require.NoError(t, err)
				assert.Equal(t, []string{"pkg1-1.0.0-r1", "pkg2-2.0.0-r2"}, request.APKs)

				// Send successful response
				response := BulkRestoreResponse{
					RestoredAPKs:   []string{"pkg1-1.0.0-r1", "pkg2-2.0.0-r2"},
					FailedRestores: []FailedRestore{},
				}
				responseBytes, err := json.Marshal(response)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(responseBytes)
			},
			authToken:   "test-token",
			expectError: false,
		},
		{
			name:     "response with partial failures",
			packages: []string{"pkg1-1.0.0-r1", "pkg2-2.0.0-r2", "pkg3-3.0.0-r3"},
			serverResponse: func(w http.ResponseWriter, _ *http.Request) {
				// Send response with some failures
				response := BulkRestoreResponse{
					RestoredAPKs: []string{"pkg1-1.0.0-r1", "pkg3-3.0.0-r3"},
					FailedRestores: []FailedRestore{
						{Name: "pkg2-2.0.0-r2", ErrorMessage: "Package not found in repository"},
					},
				}
				responseBytes, err := json.Marshal(response)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(responseBytes)
			},
			authToken:   "test-token",
			expectError: false,
		},
		{
			name:     "server returns 400",
			packages: []string{"invalid-package"},
			serverResponse: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("Invalid package format"))
			},
			authToken:     "test-token",
			expectError:   true,
			errorContains: "POST request failed with status 400: Invalid package format",
		},
		{
			name:     "server returns invalid JSON",
			packages: []string{"pkg1-1.0.0-r1"},
			serverResponse: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("invalid json"))
			},
			authToken:     "test-token",
			expectError:   true,
			errorContains: "unmarshaling response:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(tt.serverResponse))
			defer server.Close()

			// Test the makePostRequest function
			ctx := context.Background()
			err := makePostRequest(ctx, server.URL, tt.authToken, tt.packages)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestIsValidPackageFormat(t *testing.T) {
	tests := []struct {
		name     string
		pkg      string
		expected bool
	}{
		{"valid package format", "test-pkg-1.2.3-r4", true},
		{"valid with complex name", "my-complex-package-name-2.1.0-r1", true},
		{"invalid - no revision", "test-pkg-1.2.3", false},
		{"invalid - too few parts", "pkg-1.2", false},
		{"invalid - revision not starting with r", "test-pkg-1.2.3-a4", false},
		{"invalid - revision with non-numeric", "test-pkg-1.2.3-r4a", false},
		{"valid - zero revision", "test-1.2.3-r0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidPackageFormat(tt.pkg)
			assert.Equal(t, tt.expected, result)
		})
	}
}
