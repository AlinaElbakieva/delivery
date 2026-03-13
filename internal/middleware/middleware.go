package middleware

import (
	"net/http"
	"strings"

	"my_project/delivery_bot/backend/auth-service/internal/crypto"
	"my_project/delivery_bot/backend/auth-service/pkg/auth_errors"

	"github.com/labstack/echo/v4"
)

func JWTMiddleware(jwtSvc *crypto.JWTService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, "missing authorization header")
			}
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			_, claims, err := jwtSvc.ValidateToken(tokenStr, crypto.AccessToken)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, auth_errors.ErrInvalidCredentials)
			}
			c.Set("user_id", claims["sub"])
			c.Set("username", claims["username"])
			c.Set("role", claims["role"])
			return next(c)
		}
	}
}
