package login

import (
	"encoding/json"
	"errors"
	"net/http"
)

// type User struct {
// 	Username string `json:"username"`
// 	Email    string `json:"email,omitempty"`
// 	Password string `json:"password"`
// }

var users = map[string]User{} // Simulate a user database

// RegisterUser handles user registration
func RegisterUser(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if _, exists := users[user.Username]; exists {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	users[user.Username] = user
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

// LoginUser handles user login
func LoginUser(w http.ResponseWriter, r *http.Request) {
	var credentials User
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user, exists := users[credentials.Username]
	if !exists || user.Password != credentials.Password {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Login successful"})
}

// Helper function for validating user credentials (if needed elsewhere)
func ValidateCredentials(username, password string) error {
	user, exists := users[username]
	if !exists || user.Password != password {
		return errors.New("invalid credentials")
	}
	return nil
}
