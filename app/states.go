package app

import (
	"encoding/json"
	"net/http"
	"strings"
)

func ListStates(w http.ResponseWriter, r *http.Request) {
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

	var countryID int
	err = DB.QueryRow("SELECT id FROM countries WHERE name = ?", country).Scan(&countryID)
	if err != nil {
		http.Error(w, "Error retrieving country", http.StatusInternalServerError)
		return
	}

	rows, err := DB.Query("SELECT * FROM states WHERE country_id = ?", countryID)
	if err != nil {
		http.Error(w, "Error retrieving states", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var states []State
	for rows.Next() {
		var state State
		state.Country = country
		var temp int
		err := rows.Scan(&state.ID, &state.Name, &temp)
		if err != nil {
			http.Error(w, "Error scanning state", http.StatusInternalServerError)
			return
		}
		states = append(states, state)
	}

	json.NewEncoder(w).Encode(states)
}
