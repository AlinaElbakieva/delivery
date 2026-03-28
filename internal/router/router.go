package router

import (
	helper "my_project/delivery_bot/backend/auth-service/internal"
	http_delivery "my_project/delivery_bot/backend/auth-service/internal/handler"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Router struct {
	authHandler *http_delivery.AuthHandler
}

func NewRouter(authHandler *http_delivery.AuthHandler) *Router {
	return &Router{authHandler: authHandler}
}

type CustomValidator struct {
	Validator *validator.Validate
}

func (cv *CustomValidator) Validate(i interface{}) error {
	return cv.Validator.Struct(i)
}

func (r *Router) Setup() *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{"http://localhost:3000", "http://127.0.0.1:3000"}, // for local test
		AllowMethods:     []string{echo.GET, echo.POST, echo.PUT, echo.DELETE, echo.OPTIONS},
		AllowHeaders:     []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
		AllowCredentials: true,
	}))

	v := validator.New()
	v.RegisterValidation("password", helper.PasswordValidation)
	e.Validator = &CustomValidator{Validator: v}

	apiV1 := e.Group("/api/v1")

	apiV1.POST("/register", r.authHandler.Register)
	apiV1.POST("/login", r.authHandler.Login)
	apiV1.GET("/email/confirm", r.authHandler.ConfirmEmail)
	apiV1.POST("/email/confirm", r.authHandler.ConfirmEmail)
	apiV1.POST("/refresh", r.authHandler.Refresh)
	apiV1.POST("/password/forgot", r.authHandler.ForgotPassword)
	apiV1.POST("/password/reset", r.authHandler.ResetPassword)
	return e
}
