package domain

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	Id            uuid.UUID
	UserName      string
	Email         string
	Password      string
	Role          string
	Street        string
	House         string
	Apartment     string
	Entrance      string
	IsActive      bool
	EmailVerified bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     *time.Time
}
