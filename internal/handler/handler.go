package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/go-playground/validator"
	"github.com/hasanm95/go-auth-gatekeeper/internal/model"
	"github.com/hasanm95/go-auth-gatekeeper/internal/service"
)

type Handler struct {
	svc service.UserService
}

func Newhandler(svc service.UserService) *Handler {
	return &Handler{
		svc: svc,
	}
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	fmt.Print("req incoming")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed!!!", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()

	var req model.RegisterRequest

	err := json.NewDecoder(r.Body).Decode(&req)


	if err != nil {
		if errors.Is(err, io.EOF){
			http.Error(w, "Request body cannot be empty", http.StatusBadRequest)
			return;
		}

		http.Error(w, fmt.Sprintf("Malformed JSON: %v", err), http.StatusBadRequest)
		return
	}

	var validate = validator.New()

	if err := validate.Struct(req); err != nil {
		http.Error(w, fmt.Sprintf("validation failed: %v", err), http.StatusBadRequest)
		return
	}

	user, err := h.svc.RegisterUser(r.Context(), req.Email, req.Password)

	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			http.Error(w, "email already registered!!!!!!!", http.StatusConflict)
			return
		}
		log.Printf("register error: %v", err) // log full detail server-side
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	response := model.RegisterResponse{
		ID: user.ID,
		Email: user.Email,
		CreatedAt: user.CreatedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	json.NewEncoder(w).Encode(response)
}