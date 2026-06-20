package model

import (
	"context"
	"time"
)

type User struct {
	ID int64 `json:"id"`
	Email string `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	PasswordHash string `json:"-"`
}

type RegisterRequest struct {
	Email string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,gte=8"`
}

type RegisterResponse struct {
	ID int64 `json:"id"`
	Email string `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type UserRepository interface {
	CreateUser (ctx context.Context, email string, password string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByID(ctx context.Context, id int64) (*User, error)
}

type LoginRequest struct {
	Email string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,gte=8"`
}

type LoginResponse struct {
	AccessToken string `json:"access_token"`
}