package app

import (
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func Signup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := r.FormValue("email")
	password := r.FormValue("password")
	name := r.FormValue("name")
	user := User{Name: name, Email: email, Password: password}
	
	if user.Name == "" || user.Email == "" || user.Password == "" {
		http.Error(w, "Name, email and password are required", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	apiKey := generateAPIKey()

	_, err = DB.Exec("INSERT INTO users (name, email, password, api_key) VALUES (?, ?, ?, ?)",
		user.Name, user.Email, hashedPassword, apiKey)
	if err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	user.Password = "" // Remove password from response
	json.NewEncoder(w).Encode(user)
}

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	var storedPassword string
	var apiKey string
	err := DB.QueryRow("SELECT password, api_key FROM users WHERE email = ?", email).Scan(&storedPassword, &apiKey)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password)) != nil {
		http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
		return
	}

	tokenString, err := createAccessToken(email, apiKey)
	if err != nil {
		http.Error(w, "Error creating access token", http.StatusInternalServerError)
		return
	}

	response := map[string]string{"access_token": tokenString, "token_type": "bearer"}
	json.NewEncoder(w).Encode(response)
}
