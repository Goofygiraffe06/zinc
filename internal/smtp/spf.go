package smtpserver

import (
	"context"
	"net"

	"blitiri.com.ar/go/spf"
	"github.com/Goofygiraffe06/zinc/internal/logging"
)

// SPFResult represents the result of an SPF check.
type SPFResult int

const (
	SPFNone SPFResult = iota
	SPFNeutral
	SPFPass
	SPFFail
	SPFSoftFail
	SPFTempError
	SPFPermError
)

func (r SPFResult) String() string {
	switch r {
	case SPFNone:
		return "none"
	case SPFNeutral:
		return "neutral"
	case SPFPass:
		return "pass"
	case SPFFail:
		return "fail"
	case SPFSoftFail:
		return "softfail"
	case SPFTempError:
		return "temperror"
	case SPFPermError:
		return "permerror"
	default:
		return "unknown"
	}
}

// using the blitiri.com.ar/go/spf library.
type SPFChecker struct{}

// NewSPFChecker creates a new SPF checker.
func NewSPFChecker() *SPFChecker {
	return &SPFChecker{}
}

func (s *SPFChecker) CheckSPF(ctx context.Context, senderIP, senderEmail string) (SPFResult, error) {
	// Parse sender IP
	ip := net.ParseIP(senderIP)
	if ip == nil {
		logging.DebugLog("SPF check: invalid IP address: %s", senderIP)
		return SPFNone, nil
	}

	result, err := spf.CheckHostWithSender(ip, senderEmail, senderEmail)

	// Map library result to our result type
	var spfResult SPFResult
	switch result {
	case spf.Pass:
		spfResult = SPFPass
	case spf.Fail:
		spfResult = SPFFail
	case spf.SoftFail:
		spfResult = SPFSoftFail
	case spf.Neutral:
		spfResult = SPFNeutral
	case spf.None:
		spfResult = SPFNone
	case spf.TempError:
		spfResult = SPFTempError
	case spf.PermError:
		spfResult = SPFPermError
	default:
		spfResult = SPFNone
	}

	if err != nil {
		logging.WarnLog("SPF check error for email=%s ip=%s: %v", senderEmail, senderIP, err)
		return spfResult, err
	}

	logging.DebugLog("SPF check result=%s for email=%s ip=%s", spfResult.String(), senderEmail, senderIP)
	return spfResult, nil
}
