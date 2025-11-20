package smtpserver

import (
	"bytes"
	"context"
	"io"

	"github.com/Goofygiraffe06/zinc/internal/logging"
	"github.com/emersion/go-msgauth/dkim"
)

type DKIMResult int

const (
	DKIMNone DKIMResult = iota
	DKIMPass
	DKIMFail
	DKIMTempError
	DKIMPermError
)

func (r DKIMResult) String() string {
	switch r {
	case DKIMNone:
		return "none"
	case DKIMPass:
		return "pass"
	case DKIMFail:
		return "fail"
	case DKIMTempError:
		return "temperror"
	case DKIMPermError:
		return "permerror"
	default:
		return "unknown"
	}
}

// using the emersion/go-msgauth library.
type DKIMChecker struct{}

// NewDKIMChecker creates a new DKIM checker.
func NewDKIMChecker() *DKIMChecker {
	return &DKIMChecker{}
}

// CheckDKIM performs DKIM verification on the email message.
// messageData should contain the full email including headers and body.
func (d *DKIMChecker) CheckDKIM(ctx context.Context, messageData []byte) (DKIMResult, error) {
	// Create a reader from the message data
	r := bytes.NewReader(messageData)

	// Verify DKIM signatures using the library
	verifications, err := dkim.Verify(r)
	if err != nil {
		logging.WarnLog("DKIM check error: %v", err)
		return DKIMTempError, err
	}

	// Check if we have any verifications
	if len(verifications) == 0 {
		logging.DebugLog("DKIM check: no DKIM signatures found")
		return DKIMNone, nil
	}

	// Check verification results - if at least one signature is valid, consider it passed
	hasValidSignature := false
	var lastErr error

	for _, verification := range verifications {
		if verification.Err == nil {
			hasValidSignature = true
			logging.DebugLog("DKIM check: valid signature found for domain=%s", verification.Domain)
			break
		} else {
			lastErr = verification.Err
			logging.DebugLog("DKIM check: signature verification failed for domain=%s: %v",
				verification.Domain, verification.Err)
		}
	}

	if hasValidSignature {
		return DKIMPass, nil
	}

	// All signatures failed
	if lastErr != nil {
		logging.WarnLog("DKIM check: all signatures failed, last error: %v", lastErr)
		return DKIMFail, lastErr
	}

	return DKIMFail, nil
}

// readMessageData reads the complete message data from an io.Reader.
func readMessageData(r io.Reader, maxBytes int64) ([]byte, error) {
	buf := new(bytes.Buffer)
	_, err := io.Copy(buf, io.LimitReader(r, maxBytes))
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
