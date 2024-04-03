package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Database Configuration
import "os"
var(
	dbUser     = env("DB_USER", "user")
	dbPassword = env("DB_PASSWORD", "password")
	dbName     = env("DB_NAME", "locations")
	dbHost     = env("DB_HOST", "localhost")
	dbPort    = env("DB_PORT", "3306")
)

func env(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

var db *sql.DB

// Authentication Configuration
var (
	secretKey                  = []byte("your-secret-key")
	accessTokenExpireDuration = 24 * time.Hour
)

// User struct
type User struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Country struct
type Country struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Iso2      string `json:"iso2"`
	PhoneCode string `json:"phone_code"`
}

// State struct
type State struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	CountryID  int    `json:"country_id"`
}

// City struct
type City struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	State   string `json:"state"`
	Country string `json:"country"`
}

// Signup endpoint
func signup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	apiKey := generateAPIKey()

	_, err = db.Exec("INSERT INTO users (name, email, password, api_key) VALUES (?, ?, ?, ?)",
		user.Name, user.Email, hashedPassword, apiKey)
	if err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	user.Password = "" // Remove password from response
	json.NewEncoder(w).Encode(user)
}

// Login endpoint
func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	var storedPassword string
	var apiKey string
	err := db.QueryRow("SELECT password, api_key FROM users WHERE email = ?", email).Scan(&storedPassword, &apiKey)
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

// List countries endpoint
func listCountries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authorization := r.Header.Get("Authorization")
	if authorization == "" || !strings.HasPrefix(authorization, "Bearer ") {
		http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := strings.Split(authorization, " ")[1]
	payload, err := decodeAccessToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	apiKey := payload["api_key"].(string)
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE api_key = ?", apiKey).Scan(&count)
	if err != nil || count == 0 {
		http.Error(w, "Invalid API key", http.StatusUnauthorized)
		return
	}

	rows, err := db.Query("SELECT * FROM countries")
	if err != nil {
		http.Error(w, "Error retrieving countries", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var countries []Country
	for rows.Next() {
		var country Country
		err := rows.Scan(&country.ID, &country.Name, &country.Iso2, &country.PhoneCode)
		if err != nil {
			http.Error(w, "Error scanning country", http.StatusInternalServerError)
			return
		}
		countries = append(countries, country)
	}

	json.NewEncoder(w).Encode(countries)
}

// List states endpoint
func listStates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authorization := r.Header.Get("Authorization")
	if authorization == "" || !strings.HasPrefix(authorization, "Bearer ") {
		http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := strings.Split(authorization, " ")[1]
	payload, err := decodeAccessToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	apiKey := payload["api_key"].(string)
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE api_key = ?", apiKey).Scan(&count)
	if err != nil || count == 0 {
		http.Error(w, "Invalid API key", http.StatusUnauthorized)
		return
	}

	country := r.PathValue("country")

	var countryID int
	err = db.QueryRow("SELECT id FROM countries WHERE name = ?", country).Scan(&countryID)
	if err != nil {
		http.Error(w, "Error retrieving country", http.StatusInternalServerError)
		return
	}

	rows, err := db.Query("SELECT * FROM states WHERE country_id = ?", countryID)
	if err != nil {
		http.Error(w, "Error retrieving states", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var states []State
	for rows.Next() {
		var state State
		err := rows.Scan(&state.ID, &state.Name, &state.CountryID)
		if err != nil {
			http.Error(w, "Error scanning state", http.StatusInternalServerError)
			return
		}
		states = append(states, state)
	}

	json.NewEncoder(w).Encode(states)
}

// List cities endpoint
func listCities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authorization := r.Header.Get("Authorization")
	if authorization == "" || !strings.HasPrefix(authorization, "Bearer ") {
		http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := strings.Split(authorization, " ")[1]
	payload, err := decodeAccessToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	apiKey := payload["api_key"].(string)
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE api_key = ?", apiKey).Scan(&count)
	if err != nil || count == 0 {
		http.Error(w, "Invalid API key", http.StatusUnauthorized)
		return
	}

	country := r.PathValue("country")
	state := r.PathValue("state")

	var countryID int
	err = db.QueryRow("SELECT id FROM countries WHERE name = ?", country).Scan(&countryID)
	if err != nil {
		http.Error(w, "Error retrieving country", http.StatusInternalServerError)
		return
	}

	var stateID int
	err = db.QueryRow("SELECT id FROM states WHERE name = ? AND country_id = ?", state, countryID).Scan(&stateID)
	if err != nil {
		http.Error(w, "Error retrieving state", http.StatusInternalServerError)
		return
	}

	rows, err := db.Query("SELECT * FROM cities WHERE country_id = ? AND state_id = ?", countryID, stateID)
	if err != nil {
		http.Error(w, "Error retrieving cities", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var cities []City
	for rows.Next() {
		var city City
		err := rows.Scan(&city.ID, &city.Name, &city.State, &city.Country)
		if err != nil {
			http.Error(w, "Error scanning city", http.StatusInternalServerError)
			return
		}
		cities = append(cities, city)
	}

	json.NewEncoder(w).Encode(cities)
}

// Generate API key
func generateAPIKey() string {
	return uuid.New().String()
}

// Create access token
func createAccessToken(email, apiKey string) (string, error) {
	claims := jwt.MapClaims{
		"sub":    email,
		"api_key": apiKey,
		"exp":    time.Now().Add(accessTokenExpireDuration).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

// Decode access token
func decodeAccessToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token")
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return token.Claims.(jwt.MapClaims), nil
}

func main() {
	var err error
	db, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPassword, dbHost, dbPort, dbName))
	if err != nil {
		log.Fatal("Error connecting to database: ", err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatal("Error pinging database: ", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/signup", signup)
	mux.HandleFunc("POST /api/login", login)
	mux.HandleFunc("GET /api/locations", listCountries)
	mux.HandleFunc("GET /api/locations/{country}", listStates)
	mux.HandleFunc("GET /api/locations/{country}/{state}", listCities)
	log.Fatal(http.ListenAndServe(":8080", mux))
}
