package utils

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestErrorCapitalizesMessage(t *testing.T) {
	resp := Error("bad access token.")
	require.Equal(t, "error", resp["status"])
	require.Equal(t, "Bad access token.", resp["message"])
}

func TestSuccessWrapsData(t *testing.T) {
	payload := map[string]string{"ok": "yes"}
	resp := Success(payload)
	require.Equal(t, "success", resp["status"])
	require.NotZero(t, resp["timestamp"])
	require.Equal(t, payload, resp["result"])
}

func TestWPValidationErrors(t *testing.T) {
	handler := WP(func(c *gin.Context) (int, any) {
		var in struct {
			Email string `json:"email" binding:"required,email"`
		}
		if err := c.ShouldBindJSON(&in); err != nil {
			return http.StatusBadRequest, err
		}
		return http.StatusOK, map[string]string{"ok": "yes"}
	})

	t.Run("Missing required field", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{}`))
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		handler(ctx)

		require.Equal(t, http.StatusBadRequest, w.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		require.Equal(t, "error", body["status"])
		require.Equal(t, "Email is required.", body["message"])
	})

	t.Run("Invalid email format", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"email":"not-an-email"}`))
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		handler(ctx)

		require.Equal(t, http.StatusBadRequest, w.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		require.Equal(t, "error", body["status"])
		require.Equal(t, "Email must be valid", body["message"])
	})

	t.Run("Valid payload", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"email":"user@example.com"}`))
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = req

		handler(ctx)

		require.Equal(t, http.StatusOK, w.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		require.Equal(t, "success", body["status"])
		require.Equal(t, map[string]any{"ok": "yes"}, body["result"])
	})
}

