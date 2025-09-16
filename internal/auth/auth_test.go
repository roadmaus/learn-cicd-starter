package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("no authorization header", func(t *testing.T) {
		headers := http.Header{}
		_, err := GetAPIKey(headers)
		if err != ErrNoAuthHeaderIncluded {
			t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
		}
	})

	t.Run("malformed authorization header - wrong prefix", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer sometoken")

		_, err := GetAPIKey(headers)
		if err == nil || err.Error() != "malformed authorization header" {
			t.Errorf("expected malformed authorization header error, got %v", err)
		}
	})

	t.Run("malformed authorization header - missing value", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey")

		_, err := GetAPIKey(headers)
		if err == nil || err.Error() != "malformed authorization header" {
			t.Errorf("expected malformed authorization header error, got %v", err)
		}
	})

	t.Run("valid authorization header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey my-secret")

		got, err := GetAPIKey(headers)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		want := "my-secret"
		if got != want {
			t.Errorf("expected %v, got %v", want, got)
		}
	})
}
