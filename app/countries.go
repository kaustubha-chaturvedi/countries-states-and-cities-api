package app

import (
	"encoding/json"
	"net/http"
	"strings"
)

func ListCountries(w http.ResponseWriter, r *http.Request) {
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

	rows, err := DB.Query("SELECT * FROM countries")
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
