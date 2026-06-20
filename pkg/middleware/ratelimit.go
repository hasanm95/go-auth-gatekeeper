package middleware

import (
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

func RateLimitMiddleware(redisClient *redis.Client, limit int, window time.Duration, keyPrefix string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			key := keyPrefix + ":" + ip
			count, err := redisClient.Incr(r.Context(), key).Result()

			if err != nil {
				RespondWithError(w, http.StatusInternalServerError, "something went wrong")
				return 
			}

			if count == 1 {
				redisClient.Expire(r.Context(), key, window)
			}

			if count > int64(limit) {
				RespondWithError(w, http.StatusTooManyRequests, "too many requests, try again later")
				return 
			}

			next.ServeHTTP(w, r)
		})
	}
}