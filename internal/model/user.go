package model

import "time"

type User struct {
	ID int `json:"id"`
	Email string `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	PasswordHash string `json:"-"`
}

type RegisterRequest struct {
	Email string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,gte=8"`
}

type RegisterResponse struct {
	ID int `json:"id"`
	Email string `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}