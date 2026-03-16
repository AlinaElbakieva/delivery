package helper

import (
	"fmt"
	"unicode"

	"github.com/go-playground/validator/v10"
)

func PasswordValidation(fl validator.FieldLevel) bool {
	pass := fl.Field().String()

	if len(pass) < 6 {
		return false
	}

	hasLetter := false
	hasDigit := false
	hasSpecial := false

	for _, c := range pass {
		switch {
		case unicode.IsLetter(c):
			hasLetter = true
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpecial = true
		}
	}

	return hasLetter && hasDigit && hasSpecial
}

func SendOTPFake(username, code string) error {
	fmt.Printf("OTP для %s: %s\n", username, code)
	return nil
}

func SendConfirmEmailFake(email, link string) error {
	fmt.Printf("Confirm email for %s: %s\n", email, link)
	return nil
}

func SendResetPasswordEmailFake(email, link string) error {
	fmt.Printf("Reset password email for %s: %s\n", email, link)
	return nil
}
