package tests

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func LoginAs(t *testing.T, client *http.Client, username, password string) APIResponse {
	return DoPost(t, client, "/auth", fmt.Sprintf("username=%s&password=%s", username, password))
}

func TestLogin(t *testing.T) {
	client := InitClient(t)
	t.Run("Correct credentials", func(t *testing.T) {
		r := LoginAs(t, client, "Smaug", "41258")
		assert.Equal(t, "success", r.Status)
		assert.Equal(t, 200, r.StatusCode)
		assert.Equal(t, IsValidUser(t, r), true)

		// Check if token is present in cookies
		url, err := url.Parse(BaseURL)
		if err != nil {
			t.Fatalf("Failed to parse base URL: %v", err)
		}
		cookies := client.Jar.Cookies(url)
		assert.Len(t, cookies, 2)
		assert.Equal(t, "Authorization", cookies[0].Name)
		assert.Equal(t, "RefreshToken", cookies[1].Name)

	})
	t.Run("Incorrect credentials", func(t *testing.T) {
		client := InitClient(t)
		r := LoginAs(t, client, "Smaug", "wrongpassword")
		assert.Equal(t, "error", r.Status)
		assert.Equal(t, 401, r.StatusCode)
		assert.Equal(t, "Invalid credentials", r.Message)
	})
	t.Run("Missing username", func(t *testing.T) {
		client := InitClient(t)
		r := LoginAs(t, client, "", "password")
		assert.Equal(t, "error", r.Status)
		assert.Equal(t, 400, r.StatusCode)
		assert.Equal(t, "Username is required.", r.Message)
	})
	t.Run("Missing password", func(t *testing.T) {
		client := InitClient(t)
		r := LoginAs(t, client, "username", "")
		assert.Equal(t, "error", r.Status)
		assert.Equal(t, 400, r.StatusCode)
		assert.Equal(t, "Password is required.", r.Message)
	})
	t.Run("Missing credentials", func(t *testing.T) {
		client := InitClient(t)
		r := LoginAs(t, client, "", "")
		assert.Equal(t, "error", r.Status)
		assert.Equal(t, 400, r.StatusCode)
		assert.Equal(t, "Username is required. Password is required.", r.Message)
	})

	t.Run("Refresh with valid token", func(t *testing.T) {
		client := InitClient(t)
		r := LoginAs(t, client, "Smaug", "41258")
		assert.Equal(t, "success", r.Status)

		refreshResp := DoPost(t, client, "/auth/refresh", nil)
		assert.Equal(t, "success", refreshResp.Status)
		assert.Equal(t, 200, refreshResp.StatusCode)
		assert.Equal(t, IsValidUser(t, refreshResp), true)
	})

	t.Run("Refresh missing token", func(t *testing.T) {
		client := InitClient(t)
		refreshResp := DoPost(t, client, "/auth/refresh", nil)
		assert.Equal(t, "error", refreshResp.Status)
		assert.Equal(t, 401, refreshResp.StatusCode)
		assert.Equal(t, "No refresh token provided", refreshResp.Message)
	})

	t.Run("Refresh invalid token", func(t *testing.T) {
		client := InitClient(t)
		u, err := url.Parse(BaseURL)
		if err != nil {
			t.Fatalf("Failed to parse base URL: %v", err)
		}
		client.Jar.SetCookies(u, []*http.Cookie{
			{Name: "RefreshToken", Value: "invalid"},
		})
		refreshResp := DoPost(t, client, "/auth/refresh", nil)
		assert.Equal(t, "error", refreshResp.Status)
		assert.Equal(t, 401, refreshResp.StatusCode)
		assert.Equal(t, "Invalid refresh token", refreshResp.Message)
	})

	t.Run("Logout clears session", func(t *testing.T) {
		client := InitClient(t)
		loginResp := LoginAs(t, client, "Smaug", "41258")
		assert.Equal(t, "success", loginResp.Status)

		logoutResp := DoPost(t, client, "/auth/logout", nil)
		assert.Equal(t, "success", logoutResp.Status)
		assert.Equal(t, 200, logoutResp.StatusCode)
		assert.Equal(t, "Logged out successfully.", logoutResp.Message)
	})

	t.Run("Logout without token", func(t *testing.T) {
		client := InitClient(t)
		logoutResp := DoPost(t, client, "/auth/logout", nil)
		assert.Equal(t, "error", logoutResp.Status)
		assert.Equal(t, 401, logoutResp.StatusCode)
		assert.Equal(t, "No refresh token provided", logoutResp.Message)
	})

	t.Run("Logout with invalid token", func(t *testing.T) {
		client := InitClient(t)
		u, err := url.Parse(BaseURL)
		if err != nil {
			t.Fatalf("Failed to parse base URL: %v", err)
		}
		client.Jar.SetCookies(u, []*http.Cookie{
			{Name: "RefreshToken", Value: "invalid"},
		})
		logoutResp := DoPost(t, client, "/auth/logout", nil)
		assert.Equal(t, "error", logoutResp.Status)
		assert.Equal(t, 401, logoutResp.StatusCode)
		assert.Equal(t, "Invalid refresh token", logoutResp.Message)
	})

	t.Run("Logout all devices", func(t *testing.T) {
		client := InitClient(t)
		loginResp := LoginAs(t, client, "Smaug", "41258")
		assert.Equal(t, "success", loginResp.Status)

		logoutAllResp := DoPost(t, client, "/auth/logout/all", nil)
		assert.Equal(t, "success", logoutAllResp.Status)
		assert.Equal(t, 200, logoutAllResp.StatusCode)
		assert.Equal(t, "Logged out from all devices successfully.", logoutAllResp.Message)
	})

	t.Run("Logout all devices unauthorized", func(t *testing.T) {
		client := InitClient(t)
		resp := DoPost(t, client, "/auth/logout/all", nil)
		assert.Equal(t, "error", resp.Status)
		assert.Equal(t, 401, resp.StatusCode)
		assert.Equal(t, "Bad access token.", resp.Message)
	})

	t.Run("Request reset password missing username", func(t *testing.T) {
		client := InitClient(t)
		resp := DoPost(t, client, "/auth/request-reset", map[string]any{})
		assert.Equal(t, "error", resp.Status)
		assert.Equal(t, 400, resp.StatusCode)
		assert.Equal(t, "User is required.", resp.Message)
	})

	t.Run("Reset password invalid token", func(t *testing.T) {
		client := InitClient(t)
		resp := DoPost(t, client, "/auth/reset-password", map[string]any{
			"token":    "invalid-token",
			"password": "new-password",
		})
		assert.Equal(t, "error", resp.Status)
		assert.Equal(t, 400, resp.StatusCode)
		assert.Equal(t, "Invalid reset token", resp.Message)
	})
}
