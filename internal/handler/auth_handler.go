package http

import (
	"net/http"

	"my_project/delivery_bot/backend/auth-service/internal/domain"
	"my_project/delivery_bot/backend/auth-service/internal/usecase"
	"my_project/delivery_bot/backend/auth-service/pkg/auth_errors"

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
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "the user has been successfully registered"})
}

func (h *AuthHandler) Login(c echo.Context) error {
	ctx := c.Request().Context()

	req := domain.RequestLogin{}
	if err := c.Bind(&req); err != nil {
		h.logger.Warn("Invalid login request", zap.Error(err))
		return echo.NewHTTPError(http.StatusBadRequest, auth_errors.ErrInvalidRequest)
	}
	if err := c.Validate(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, auth_errors.ErrInvalidRequest)
	}
	if err := h.usecase.Login(ctx, req.Username, req.Password); err != nil {
		h.logger.Warn("Login failed", zap.Error(err))
		return echo.NewHTTPError(http.StatusUnauthorized, auth_errors.ErrUserNotFound)
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "OTP sent"})
}

func (h *AuthHandler) VerifyOTP(c echo.Context) error {
	ctx := c.Request().Context()
	req := domain.RequestOTP{}
	if err := c.Bind(&req); err != nil {
		h.logger.Warn("Invalid OTP request", zap.Error(err))
		return echo.NewHTTPError(http.StatusBadRequest, auth_errors.ErrInvalidRequest)
	}
	access, refresh, err := h.usecase.VerifyOTP(ctx, req.Username, req.Code)
	if err != nil {
		h.logger.Warn("OTP verification failed", zap.Error(err))
		return echo.NewHTTPError(http.StatusUnauthorized, auth_errors.ErrInvalidOTP)
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
