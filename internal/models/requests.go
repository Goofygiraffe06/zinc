package models

type RegisterInitRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type RegisterCompleteRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Username  string `json:"username" validate:"required"`
	PublicKey string `json:"public_key" validate:"required"`
	Nonce     string `json:"nonce" validate:"required"`
	Signature string `json:"signature" validate:"required"`
}

type LoginInitRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type LoginVerifyRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Signature string `json:"signature" validate:"required"`
}
