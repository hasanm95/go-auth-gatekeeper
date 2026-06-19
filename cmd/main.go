package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/hasanm95/go-auth-gatekeeper/internal/config"
)

func main(){
	cfg, err := config.Load()

	if err != nil {
		log.Fatal(err)
	}

	baseURL := strings.TrimRight(cfg.BaseURL, "/") + "/"

	server := &http.Server{
		Addr: ":" + cfg.Port,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	fmt.Printf("Connecting server on port: %s\n", cfg.Port)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("couldn't connect server: %v", err)
	}

	fmt.Printf("Application is running on: %s\n", baseURL)
}