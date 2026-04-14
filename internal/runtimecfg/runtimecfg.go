// Package runtimecfg centralizes provider registration and session identifier handling
// shared by CLI and mobile entrypoints.
package runtimecfg

import (
	"strings"

	"github.com/openlibrecommunity/olcrtc/internal/provider"
	"github.com/openlibrecommunity/olcrtc/internal/provider/jazz"
	"github.com/openlibrecommunity/olcrtc/internal/provider/telemost"
)

const (
	// ProviderTelemost is the Yandex Telemost transport backend.
	ProviderTelemost = "telemost"
	// ProviderJazz is the SaluteJazz transport backend.
	ProviderJazz            = "jazz"
	providerSaluteJazzAlias = "salutejazz"
)

// RegisterProviders installs all built-in providers into the shared registry.
func RegisterProviders() {
	provider.Register(ProviderJazz, jazz.New)
	provider.Register(ProviderTelemost, telemost.New)
}

// NormalizeProviderName converts aliases and mixed-case input into a canonical provider name.
func NormalizeProviderName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case providerSaluteJazzAlias:
		return ProviderJazz
	default:
		return strings.ToLower(strings.TrimSpace(name))
	}
}

// IsSupportedProvider reports whether the provider name maps to a built-in backend.
func IsSupportedProvider(name string) bool {
	switch NormalizeProviderName(name) {
	case ProviderTelemost, ProviderJazz:
		return true
	default:
		return false
	}
}

// BuildRoomURL converts the user-entered session identifier into the provider-specific
// room selector expected by the runtime.
func BuildRoomURL(providerName, sessionID string) string {
	switch NormalizeProviderName(providerName) {
	case ProviderTelemost:
		return "https://telemost.yandex.ru/j/" + sessionID
	case ProviderJazz:
		return sessionID
	default:
		return sessionID
	}
}
