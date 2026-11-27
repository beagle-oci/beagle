package meta

import "testing"

func TestVulnsString(t *testing.T) {
	tests := []struct {
		v    *Vulns
		want string
	}{
		{nil, "-"},
		{&Vulns{Status: "Success"}, "clean"},
		{&Vulns{Status: "Success", Critical: 1, High: 3, Low: 2}, "C1 H3 L2"},
		{&Vulns{Status: "Running", High: 3}, "running"},
		{&Vulns{Medium: 4}, "M4"},
	}
	for _, tt := range tests {
		if got := tt.v.String(); got != tt.want {
			t.Errorf("%+v: got %q, want %q", tt.v, got, tt.want)
		}
	}
}
