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

type NonceResponse struct {
	Nonce string `json:"nonce"`
}

type VerifyResponse struct {
	Nonce string `json:"nonce"`
}

type LoginInitResponse struct {
	Nonce string `json:"nonce"`
}
