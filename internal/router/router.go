package router

import (
	helper "my_project/delivery_bot/backend/auth-service/internal"
	http_delivery "my_project/delivery_bot/backend/auth-service/internal/delivery"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
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

	v := validator.New()
	v.RegisterValidation("password", helper.PasswordValidation)
	e.Validator = &CustomValidator{Validator: v}

	apiV1 := e.Group("/api/v1")

	apiV1.POST("/register", r.authHandler.Register)
	apiV1.POST("/login", r.authHandler.Login)
	apiV1.POST("/otp/request", r.authHandler.Login) // reuse login for OTP generation
	apiV1.POST("/otp/verify", r.authHandler.VerifyOTP)
	apiV1.POST("/refresh", r.authHandler.Refresh)
	return e
}
