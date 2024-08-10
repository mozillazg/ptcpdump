package cmd

import "testing"

func Test_getPodNameFilter(t *testing.T) {
	type args struct {
		raw string
	}
	tests := []struct {
		name     string
		args     args
		wantNs   string
		wantName string
	}{
		{
			name: "include ns and name",
			args: args{
				raw: "foo.bar",
			},
			wantName: "foo",
			wantNs:   "bar",
		},
		{
			name: "name include dot",
			args: args{
				raw: "foo.bar.foobar",
			},
			wantName: "foo.bar",
			wantNs:   "foobar",
		},
		{
			name: "default ns",
			args: args{
				raw: "foobar",
			},
			wantName: "foobar",
			wantNs:   "default",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotNs := getPodNameFilter(tt.args.raw)
			if gotNs != tt.wantNs {
				t.Errorf("getPodNameFilter() gotNs = %v, want %v", gotNs, tt.wantNs)
			}
			if gotName != tt.wantName {
				t.Errorf("getPodNameFilter() gotName = %v, want %v", gotName, tt.wantName)
			}
		})
	}
}
