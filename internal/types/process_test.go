package types

import (
	"testing"
)

func TestProcessBase_MatchComm(t *testing.T) {
	tests := []struct {
		name     string
		process  ProcessBase
		commName string
		want     bool
	}{
		{"Exact match", ProcessBase{Cmd: "/usr/bin/bash"}, "bash", true},
		{"Truncated match", ProcessBase{Cmd: "/usr/bin/verylongcommandname"}, "verylongcommand", true},
		{"No match", ProcessBase{Cmd: "/usr/bin/bash"}, "sh", false},
		{"OpenWRT case", ProcessBase{Cmd: "/dev/fd/5", Args: []string{"/usr/sbin/dropbear"}}, "dropbear", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.process.MatchComm(tt.commName); got != tt.want {
				t.Errorf("MatchComm() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProcessBase_FormatArgs(t *testing.T) {
	tests := []struct {
		name    string
		process ProcessBase
		want    string
	}{
		{"No truncation", ProcessBase{Args: []string{"arg1", "arg2"}}, "arg1 arg2"},
		{"With truncation", ProcessBase{Args: []string{"arg1", "arg2"}, ArgsTruncated: true}, "arg1 arg2..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.process.FormatArgs(); got != tt.want {
				t.Errorf("FormatArgs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProcessBase_Comm(t *testing.T) {
	tests := []struct {
		name    string
		process ProcessBase
		want    string
	}{
		{"Normal command", ProcessBase{Cmd: "/usr/bin/bash"}, "bash"},
		{"OpenWRT case", ProcessBase{Cmd: "/dev/fd/5", Args: []string{"/usr/sbin/dropbear"}}, "dropbear"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.process.Comm(); got != tt.want {
				t.Errorf("Comm() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProcessExec_FilenameStr(t *testing.T) {
	tests := []struct {
		name    string
		process ProcessExec
		want    string
	}{
		{"No truncation", ProcessExec{Filename: "filename"}, "filename"},
		{"With truncation", ProcessExec{Filename: "filename", FilenameTruncated: true}, "filename..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.process.FilenameStr(); got != tt.want {
				t.Errorf("FilenameStr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProcessExec_ArgsStr(t *testing.T) {
	tests := []struct {
		name    string
		process ProcessExec
		want    string
	}{
		{"No truncation", ProcessExec{Args: []string{"arg1", "arg2"}}, "arg1 arg2"},
		{"With truncation", ProcessExec{Args: []string{"arg1", "arg2"}, ArgsTruncated: true}, "arg1 arg2..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.process.ArgsStr(); got != tt.want {
				t.Errorf("ArgsStr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProcessExec_MatchComm(t *testing.T) {
	tests := []struct {
		name     string
		process  ProcessExec
		commName string
		want     bool
	}{
		{"Exact match", ProcessExec{Filename: "/usr/bin/bash"}, "bash", true},
		{"Truncated match", ProcessExec{Filename: "/usr/bin/verylongcommandname"}, "verylongcommand", true},
		{"No match", ProcessExec{Filename: "/usr/bin/bash"}, "sh", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.process.MatchComm(tt.commName); got != tt.want {
				t.Errorf("MatchComm() = %v, want %v", got, tt.want)
			}
		})
	}
}
