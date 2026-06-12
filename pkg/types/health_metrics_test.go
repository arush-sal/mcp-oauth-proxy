package types

import "testing"

func TestResolveHealthMetricsConfig_Defaults(t *testing.T) {
	h := ResolveHealthMetricsConfig(&Config{})
	if h.HealthPath != "/healthz" {
		t.Errorf("HealthPath default = %q, want /healthz", h.HealthPath)
	}
	if h.ReadyPath != "/readyz" {
		t.Errorf("ReadyPath default = %q, want /readyz", h.ReadyPath)
	}
	if h.MetricsPath != "/metrics" {
		t.Errorf("MetricsPath default = %q, want /metrics", h.MetricsPath)
	}
	if h.EnableMetrics {
		t.Errorf("EnableMetrics default = true, want false")
	}
}

func TestResolveHealthMetricsConfig_CustomPaths(t *testing.T) {
	h := ResolveHealthMetricsConfig(&Config{
		HealthPath:  "/live",
		ReadyPath:   "/ready",
		MetricsPath: "/m",
	})
	if h.HealthPath != "/live" {
		t.Errorf("HealthPath = %q, want /live", h.HealthPath)
	}
	if h.ReadyPath != "/ready" {
		t.Errorf("ReadyPath = %q, want /ready", h.ReadyPath)
	}
	if h.MetricsPath != "/m" {
		t.Errorf("MetricsPath = %q, want /m", h.MetricsPath)
	}
}

func TestValidateHealthMetricsConfig(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		routePrefix string
		wantErr     bool
	}{
		{
			name:    "distinct defaults pass",
			cfg:     Config{},
			wantErr: false,
		},
		{
			name: "legacy health equals configured health path is allowed (dedup)",
			// prefix=="" + HealthPath=="/health" -> legacy "/health" == HealthPath.
			// The liveness probe serves that path; the legacy route is deduped, so
			// this must NOT be reported as an error.
			cfg:     Config{HealthPath: "/health"},
			wantErr: false,
		},
		{
			name: "legacy health collides with ready path rejected",
			// prefix=="" + ReadyPath=="/health" -> legacy "/health" == ReadyPath.
			// Different handlers on the same pattern: an unavoidable collision.
			cfg:     Config{ReadyPath: "/health"},
			wantErr: true,
		},
		{
			name: "legacy health collides with metrics on main mux rejected",
			// prefix=="" + MetricsPath=="/health" -> legacy "/health" == MetricsPath.
			cfg:     Config{EnableMetrics: true, MetricsPath: "/health"},
			wantErr: true,
		},
		{
			name: "legacy health with non-colliding prefix passes",
			// prefix=="/oauth2" -> legacy "/oauth2/health" collides with nothing.
			cfg:         Config{ReadyPath: "/health"},
			routePrefix: "/oauth2",
			wantErr:     false,
		},
		{
			name:    "metrics on main mux with distinct paths pass",
			cfg:     Config{EnableMetrics: true},
			wantErr: false,
		},
		{
			name:    "metrics on separate listener may reuse a probe path",
			cfg:     Config{EnableMetrics: true, MetricsAddress: ":9090", MetricsPath: "/healthz"},
			wantErr: false,
		},
		{
			name:    "health equals ready rejected",
			cfg:     Config{HealthPath: "/same", ReadyPath: "/same"},
			wantErr: true,
		},
		{
			name:    "metrics collides with health on main mux rejected",
			cfg:     Config{EnableMetrics: true, MetricsPath: "/healthz"},
			wantErr: true,
		},
		{
			name:    "metrics collides with ready on main mux rejected",
			cfg:     Config{EnableMetrics: true, MetricsPath: "/readyz"},
			wantErr: true,
		},
		{
			name:    "relative health path rejected",
			cfg:     Config{HealthPath: "healthz"},
			wantErr: true,
		},
		{
			name:    "relative ready path rejected",
			cfg:     Config{ReadyPath: "readyz"},
			wantErr: true,
		},
		{
			name:    "relative metrics path rejected when enabled",
			cfg:     Config{EnableMetrics: true, MetricsPath: "metrics"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := ResolveHealthMetricsConfig(&tt.cfg)
			err := h.Validate(tt.routePrefix)
			if tt.wantErr && err == nil {
				t.Fatalf("Validate() = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestMetricsLocationDecision(t *testing.T) {
	tests := []struct {
		name         string
		cfg          Config
		wantMainMux  bool
		wantSeparate bool
	}{
		{
			name:         "disabled",
			cfg:          Config{EnableMetrics: false},
			wantMainMux:  false,
			wantSeparate: false,
		},
		{
			name:         "enabled no address -> main mux",
			cfg:          Config{EnableMetrics: true},
			wantMainMux:  true,
			wantSeparate: false,
		},
		{
			name:         "enabled with address -> separate listener",
			cfg:          Config{EnableMetrics: true, MetricsAddress: ":9090"},
			wantMainMux:  false,
			wantSeparate: true,
		},
		{
			name:         "address set but disabled -> neither",
			cfg:          Config{EnableMetrics: false, MetricsAddress: ":9090"},
			wantMainMux:  false,
			wantSeparate: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := ResolveHealthMetricsConfig(&tt.cfg)
			if got := h.MetricsOnMainMux(); got != tt.wantMainMux {
				t.Errorf("MetricsOnMainMux() = %v, want %v", got, tt.wantMainMux)
			}
			if got := h.MetricsOnSeparateListener(); got != tt.wantSeparate {
				t.Errorf("MetricsOnSeparateListener() = %v, want %v", got, tt.wantSeparate)
			}
		})
	}
}
