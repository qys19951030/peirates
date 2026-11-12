package app

import "testing"

func TestParsePortScanArgs(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
		want      portScanOptions
		handled   bool
		wantErr   bool
	}{
		{
			name:      "positional target ports workers json",
			arguments: []string{"10.0.0.1", "22,80", "8", "json"},
			want:      portScanOptions{target: "10.0.0.1", ports: "22,80", workers: 8, json: true},
			handled:   true,
		},
		{
			name:      "named flags",
			arguments: []string{"-target", "10.0.0.0/30", "-ports", "443", "-workers", "3", "-json"},
			want:      portScanOptions{target: "10.0.0.0/30", ports: "443", workers: 3, json: true},
			handled:   true,
		},
		{
			name:      "long flags",
			arguments: []string{"--target", "10.0.0.1", "--ports", "22", "--workers", "2"},
			want:      portScanOptions{target: "10.0.0.1", ports: "22", workers: 2},
			handled:   true,
		},
		{
			name:      "no target falls through",
			arguments: []string{"-json"},
			handled:   false,
		},
		{
			name:      "bad worker count",
			arguments: []string{"10.0.0.1", "22", "-2"},
			wantErr:   true,
			handled:   true,
		},
		{
			name:      "missing ports value",
			arguments: []string{"-ports"},
			wantErr:   true,
			handled:   true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, handled, err := parsePortScanArgs(test.arguments)
			if handled != test.handled {
				t.Fatalf("handled = %v, want %v", handled, test.handled)
			}
			if test.wantErr && err == nil {
				t.Fatalf("expected error, got %+v", got)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !test.wantErr && handled && got != test.want {
				t.Fatalf("options = %+v, want %+v", got, test.want)
			}
		})
	}
}
