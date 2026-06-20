package middleware

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/hasanm95/go-auth-gatekeeper/internal/service"
)

type contextKey string

const UserIDKey contextKey = "userID"

type ErrorResponse struct {
	Error string `json:"error"`
}


func RespondWithError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}

func UserIDFromContext(ctx context.Context) (int64, bool) {
    id, ok := ctx.Value(UserIDKey).(int64)
    return id, ok
}

func AuthMiddleware(secretKey string, userService *service.UserService) func(http.Handler) http.Handler{
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")

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

			if claims.TokenType != "access" {
				RespondWithError(w, http.StatusUnauthorized, "invalid token type")
				return 
			}

			isBlackListed, err := userService.IsTokenBlackListed(r.Context(), tokenString)

			if err != nil {
				log.Printf("blacklist check failed: %v", err)
				RespondWithError(w, http.StatusInternalServerError, "Something went wrong")
				return 
			}

			if isBlackListed {
				RespondWithError(w, http.StatusUnauthorized, "token has been revoked")
				return 
			}

			ctx := context.WithValue(r.Context(), UserIDKey, claims.UserID)


			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}