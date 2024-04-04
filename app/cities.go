package app

import (
	"encoding/json"
	"net/http"
	"strings"
)

func ListCities(w http.ResponseWriter, r *http.Request) {
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
	err = DB.QueryRow("SELECT COUNT(*) FROM users WHERE api_key = ?", apiKey).Scan(&count)
	if err != nil || count == 0 {
		http.Error(w, "Invalid API key", http.StatusUnauthorized)
		return
	}

	country := r.PathValue("country")
	state := r.PathValue("state")

	var countryID int
	err = DB.QueryRow("SELECT id FROM countries WHERE name = ?", country).Scan(&countryID)
	if err != nil {
		http.Error(w, "Error retrieving country", http.StatusInternalServerError)
		return
	}

	var stateID int
	err = DB.QueryRow("SELECT id FROM states WHERE name = ? AND country_id = ?", state, countryID).Scan(&stateID)
	if err != nil {
		http.Error(w, "Error retrieving state", http.StatusInternalServerError)
		return
	}

	rows, err := DB.Query("SELECT * FROM cities WHERE country_id = ? AND state_id = ?", countryID, stateID)
	if err != nil {
		http.Error(w, "Error retrieving cities", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var cities []City
	for rows.Next() {
		var city City
		city.Country = country
		city.State = state
		var temp int
		err := rows.Scan(&city.ID, &city.Name , &temp, &temp)
		if err != nil {
			http.Error(w, "Error scanning city", http.StatusInternalServerError)
			return
		}
		cities = append(cities, city)
	}

	json.NewEncoder(w).Encode(cities)
}
