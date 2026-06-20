package model

import "errors"

var ErrUserNotFound = errors.New("user not found")
var ErrInvalidCredentials = errors.New("inavalid email or password")