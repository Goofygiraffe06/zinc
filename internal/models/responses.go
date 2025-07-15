package models

type StatusResponse struct {
	Status string `json:"status"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type TokenResponse struct {
	Token string `json:"token"`
}

type VerifyResponse struct {
	Nonce string `json:"nonce"`
}

type LoginInitResponse struct {
	Nonce string `json:"nonce"`
}

type LoginVerifyRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Signature string `json:"signature" validate:"required"`
}
