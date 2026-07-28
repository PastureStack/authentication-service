package server

import "testing"

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
