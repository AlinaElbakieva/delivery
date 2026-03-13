package domain

import "time"

type User struct {
	Id        int64
	UserName  string
	Email     string
	Password  string
	Role      string
	CreatedAt time.Time
}
