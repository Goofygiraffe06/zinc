package models

type User struct {
	Email     string `json:"email"`
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
}
