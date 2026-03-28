package domain

type RequestRegister struct {
	Username string `json:"username" validate:"required,min=3,max=50"`
	Password string `json:"password" validate:"required,password"`
	Email    string `json:"email" validate:"required,email"`
	Role     string `json:"role"`
}
