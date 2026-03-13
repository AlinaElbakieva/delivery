package domain

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	Id        uuid.UUID
	UserName  string
	Phone     string
	Email     string
	Password  string
	Role      string
	Street    string
	House     string
	Apartment string
	Entrance  string
	IsActive  bool
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}
