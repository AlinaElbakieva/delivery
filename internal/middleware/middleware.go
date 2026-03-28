package middleware

import (
	"strings"

	"my_project/delivery_bot/backend/auth-service/internal/crypto"
	"my_project/delivery_bot/backend/auth-service/pkg/auth_errors"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

func JWTMiddleware(jwtSvc *crypto.JWTService, logger *zap.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				logger.Info("JWT middleware: missing Authorization header")
				return echo.NewHTTPError(401, auth_errors.ErrInvalidToken)
			}

			if !strings.HasPrefix(authHeader, "Bearer ") {
				logger.Info("JWT middleware: invalid Authorization format")
				return echo.NewHTTPError(401, auth_errors.ErrInvalidToken)
			}

			tokenStr := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
			if tokenStr == "" {
				logger.Info("JWT middleware: empty bearer token")
				return echo.NewHTTPError(401, auth_errors.ErrInvalidToken)
			}

			claims, err := jwtSvc.ValidateToken(tokenStr, crypto.AccessToken)
			if err != nil {
				logger.Info("JWT middleware: token validation failed", zap.Error(err))
				return echo.NewHTTPError(401, auth_errors.ErrInvalidToken)
			}
			c.Set("user_id", claims.RegisteredClaims.Subject)
			c.Set("username", claims.Username)
			c.Set("role", claims.Role)
			return next(c)
		}
	}
}
