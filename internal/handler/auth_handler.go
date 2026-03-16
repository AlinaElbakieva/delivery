package http

import (
	"errors"
	"net/http"

	"my_project/delivery_bot/backend/auth-service/internal/domain"
	"my_project/delivery_bot/backend/auth-service/internal/usecase"
	"my_project/delivery_bot/backend/auth-service/pkg/auth_errors"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

type AuthHandler struct {
	usecase *usecase.AuthUseCase
	logger  *zap.Logger
}

func NewAuthHandler(u *usecase.AuthUseCase, logger *zap.Logger) *AuthHandler {
	return &AuthHandler{usecase: u, logger: logger}
}

func (h *AuthHandler) Register(c echo.Context) error {
	ctx := c.Request().Context()

	req := domain.RequestRegister{}
	if err := c.Bind(&req); err != nil {
		h.logger.Warn("Invalid register request", zap.Error(err))
		return echo.NewHTTPError(http.StatusBadRequest, auth_errors.ErrInvalidRequest)
	}
	if req.Username == "" || req.Password == "" || req.Email == "" {
		h.logger.Warn("the request fields cannot be empty")
		return echo.NewHTTPError(http.StatusBadRequest, auth_errors.ErrInvalidRequest)

	}
	if err := c.Validate(req); err != nil {
		h.logger.Warn("Validation failed", zap.Error(err))
		return echo.NewHTTPError(http.StatusBadRequest, auth_errors.ErrInvalidRequest)
	}

	if err := h.usecase.Register(ctx, req.Username, req.Password, req.Role, req.Email); err != nil {
		h.logger.Warn("Register failed", zap.Error(err))
		if errors.Is(err, auth_errors.ErrUserAlreadyExists) {
			return echo.NewHTTPError(http.StatusConflict, "user with this email already exists")
		}
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request")
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "registered; check your email to confirm"})
}

func (h *AuthHandler) Login(c echo.Context) error {
	ctx := c.Request().Context()

	var req struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required"`
	}
	if err := c.Bind(&req); err != nil {
		h.logger.Warn("Invalid login request", zap.Error(err))
		return echo.NewHTTPError(http.StatusBadRequest, auth_errors.ErrInvalidRequest)
	}
	if err := c.Validate(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, auth_errors.ErrInvalidRequest)
	}
	access, refresh, err := h.usecase.Login(ctx, req.Email, req.Password)
	if err != nil {
		h.logger.Warn("Login failed", zap.Error(err))
		if errors.Is(err, auth_errors.ErrEmailNotVerified) {
			return echo.NewHTTPError(http.StatusForbidden, "email not verified")
		}
		return echo.NewHTTPError(http.StatusUnauthorized, auth_errors.ErrInvalidCredentials)
	}
	return c.JSON(http.StatusOK, map[string]string{
		"access_token":  access,
		"refresh_token": refresh,
	})
}

func (h *AuthHandler) Refresh(c echo.Context) error {
	ctx := c.Request().Context()
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, auth_errors.ErrInvalidRequest)
	}
	access, refresh, err := h.usecase.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, auth_errors.ErrInvalidRefreshToken)
	}
	return c.JSON(http.StatusOK, map[string]string{
		"access_token":  access,
		"refresh_token": refresh,
	})
}

func (h *AuthHandler) ConfirmEmail(c echo.Context) error {
	ctx := c.Request().Context()
	tokenStr := c.QueryParam("token")
	if tokenStr == "" {
		var body struct {
			Token string `json:"token"`
		}
		_ = c.Bind(&body)
		tokenStr = body.Token
	}
	if tokenStr == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "token required")
	}
	token, err := uuid.Parse(tokenStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, auth_errors.ErrInvalidOTP)
	}
	if err := h.usecase.ConfirmEmail(ctx, token); err != nil {
		h.logger.Warn("ConfirmEmail failed", zap.Error(err))
		return echo.NewHTTPError(http.StatusBadRequest, auth_errors.ErrInvalidOTP)
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "email confirmed"})
}

func (h *AuthHandler) ForgotPassword(c echo.Context) error {
	ctx := c.Request().Context()

	var req struct {
		Email string `json:"email" validate:"required,email"`
	}

	if err := c.Bind(&req); err != nil {
		h.logger.Warn("Invalid forgot password request", zap.Error(err))
		return echo.NewHTTPError(http.StatusBadRequest, auth_errors.ErrInvalidRequest)
	}
	if err := c.Validate(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, auth_errors.ErrInvalidRequest)
	}

	if err := h.usecase.ForgotPassword(ctx, req.Email); err != nil {
		h.logger.Warn("ForgotPassword failed", zap.Error(err))
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "if this email exists, reset link was sent"})
}

func (h *AuthHandler) ResetPassword(c echo.Context) error {
	ctx := c.Request().Context()

	var req struct {
		Token    string `json:"token" validate:"required"`
		Password string `json:"password" validate:"required,password"`
	}

	if err := c.Bind(&req); err != nil {
		h.logger.Warn("Invalid reset password request", zap.Error(err))
		return echo.NewHTTPError(http.StatusBadRequest, auth_errors.ErrInvalidRequest)
	}
	if err := c.Validate(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, auth_errors.ErrInvalidRequest)
	}

	token, err := uuid.Parse(req.Token)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, auth_errors.ErrInvalidOTP)
	}

	if err := h.usecase.ResetPassword(ctx, token, req.Password); err != nil {
		h.logger.Warn("ResetPassword failed", zap.Error(err))
		return echo.NewHTTPError(http.StatusBadRequest, auth_errors.ErrInvalidOTP)
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "password has been reset"})
}
