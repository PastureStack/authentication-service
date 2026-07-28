package server

import (
	"strconv"
	"testing"
	"time"
)

func TestResolveConfiguredProviderUsesActivePlatformProvider(t *testing.T) {
	tests := []struct {
		name       string
		active     string
		remembered string
		expected   string
	}{
		{
			name:       "local authentication overrides remembered OIDC",
			active:     "localAuthConfig",
			remembered: "oidcconfig",
			expected:   "localAuthConfig",
		},
		{
			name:       "disabled authentication overrides remembered OIDC",
			active:     "none",
			remembered: "oidcconfig",
			expected:   "none",
		},
		{
			name:       "active external provider overrides stale remembered provider",
			active:     "oidcconfig",
			remembered: "githubconfig",
			expected:   "oidcconfig",
		},
		{
			name:       "legacy database falls back to remembered provider",
			active:     "",
			remembered: "oidcconfig",
			expected:   "oidcconfig",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := resolveConfiguredProvider(test.active, test.remembered)
			if actual != test.expected {
				t.Fatalf("resolved provider %q, expected %q", actual, test.expected)
			}
		})
	}
}

func TestLocalRecoveryReadyRequiresRecentVerifiedAdministrator(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	recent := strconv.FormatInt(now.Add(-time.Minute).UnixMilli(), 10)
	stale := strconv.FormatInt(now.Add(-6*time.Minute).UnixMilli(), 10)

	tests := []struct {
		name     string
		settings map[string]string
		expected bool
	}{
		{
			name: "recent verified local administrator",
			settings: map[string]string{
				localRecoveryEnabledSetting:    "true",
				localRecoveryVerifiedAtSetting: recent,
				localRecoveryMFAReadySetting:   "true",
			},
			expected: true,
		},
		{
			name: "stale verification",
			settings: map[string]string{
				localRecoveryEnabledSetting:    "true",
				localRecoveryVerifiedAtSetting: stale,
				localRecoveryMFAReadySetting:   "true",
			},
		},
		{
			name: "recovery disabled",
			settings: map[string]string{
				localRecoveryEnabledSetting:    "false",
				localRecoveryVerifiedAtSetting: recent,
				localRecoveryMFAReadySetting:   "true",
			},
		},
		{
			name: "administrator has no registered MFA factor",
			settings: map[string]string{
				localRecoveryEnabledSetting:    "true",
				localRecoveryVerifiedAtSetting: recent,
				localRecoveryMFAReadySetting:   "false",
			},
		},
		{
			name: "missing verification timestamp",
			settings: map[string]string{
				localRecoveryEnabledSetting: "true",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := localRecoveryReady(test.settings, now); actual != test.expected {
				t.Fatalf("localRecoveryReady() = %v, expected %v", actual, test.expected)
			}
		})
	}
}
