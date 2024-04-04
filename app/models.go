package app

type User struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Country struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Iso2      string `json:"iso2"`
	PhoneCode string `json:"phone_code"`
}

type State struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Country string `json:"country"`
}

type City struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	State   string `json:"state"`
	Country string `json:"country"`
}
