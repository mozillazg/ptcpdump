package cmd

import (
	"github.com/stretchr/testify/assert"
	"os"
	"path"
	"testing"
)

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

func Test_prepareOptions_exp(t *testing.T) {
	t.Run("exp arg", func(t *testing.T) {
		opts := &Options{}
		err := prepareOptions(opts, []string{"--", "curl", "1.1.1.1"},
			[]string{"port 8080", "and host 127.0.0.1"})
		assert.NoError(t, err)
		assert.Equal(t, "port 8080 and host 127.0.0.1", opts.pcapFilter)
	})

	t.Run("exp file", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "exp")
		assert.NoError(t, err)
		defer os.Remove(dir)
		fp := path.Join(dir, "test.exp")
		defer os.Remove(fp)
		err = os.WriteFile(fp, []byte("  port 8081 and tcp  \n"), 0644)
		assert.NoError(t, err)

		opts := &Options{
			expressionFile: fp,
		}
		err = prepareOptions(opts, []string{"-i", "any", "host 127.0.0.1 and port 8080"},
			[]string{"port 8080", "and host 127.0.0.1"})
		assert.NoError(t, err)
		assert.Equal(t, "port 8081 and tcp", opts.pcapFilter)
	})
}
