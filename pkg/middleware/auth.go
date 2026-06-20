package middleware

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/hasanm95/go-auth-gatekeeper/internal/service"
)

const userIDKey string = "userID"

type ErrorResponse struct {
	Error string `json:"error"`
}


func RespondWithError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}

func AuthMiddleware(secretKey string, userService *service.UserService) func(http.Handler) http.Handler{
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			log.Print("authHeader======>", authHeader)

			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				RespondWithError(w, http.StatusUnauthorized, "missing token")
				return 
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")

			claims, err := service.ValidateToken(tokenString, secretKey)

			if err != nil {
				RespondWithError(w, http.StatusUnauthorized, "invalid or expired token")
				return 
			}

			isBlackListed, err := userService.IsTokenBlackListed(r.Context(), tokenString)

			if err != nil {
				RespondWithError(w, http.StatusInternalServerError, "Something went wrong")
			}

			if isBlackListed {
				RespondWithError(w, http.StatusUnauthorized, "token has been revoked")
				return 
			}

			ctx := context.WithValue(r.Context(), userIDKey, claims.UserID)


			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}