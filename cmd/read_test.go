package cmd

import (
	"bytes"
	"context"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestFormat(t *testing.T) {
	type args struct {
		name            string
		opts            *Options
		expectedOutFile string
	}

	tests := []args{
		{
			name: "tcp",
			opts: &Options{
				readFilePath: "../testdata/format/tcp.pcapng",
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.out",
		},
		{
			name: "tcp -v",
			opts: &Options{
				readFilePath: "../testdata/format/tcp.pcapng",
				verbose:      1,
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-v.out",
		},
		{
			name: "tcp -q",
			opts: &Options{
				readFilePath: "../testdata/format/tcp.pcapng",
				quiet:        true,
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-q.out",
		},
		{
			name: "tcp -A",
			opts: &Options{
				readFilePath:     "../testdata/format/tcp.pcapng",
				printDataAsASCII: true,
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-A.out",
		},
		{
			name: "tcp -x",
			opts: &Options{
				readFilePath:   "../testdata/format/tcp.pcapng",
				printDataAsHex: 1,
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-x.out",
		},
		{
			name: "tcp -xx",
			opts: &Options{
				readFilePath:   "../testdata/format/tcp.pcapng",
				printDataAsHex: 2,
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-xx.out",
		},
		{
			name: "tcp -X",
			opts: &Options{
				readFilePath:        "../testdata/format/tcp.pcapng",
				printDataAsHexASCII: 1,
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-X.out",
		},
		{
			name: "tcp -XX",
			opts: &Options{
				readFilePath:        "../testdata/format/tcp.pcapng",
				printDataAsHexASCII: 2,
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-XX.out",
		},
		{
			name: "mptcp",
			opts: &Options{
				readFilePath: "../testdata/format/mptcp.pcap",
			},
			expectedOutFile: "../testdata/format/mptcp.pcap.out",
		},
		{
			name: "tfo and sack",
			opts: &Options{
				readFilePath: "../testdata/format/tfo.pcap",
			},
			expectedOutFile: "../testdata/format/tfo.pcap.out",
		},
		{
			name: "udp",
			opts: &Options{
				readFilePath: "../testdata/format/udp.pcap",
			},
			expectedOutFile: "../testdata/format/udp.pcap.out",
		},
		{
			name: "udp dns",
			opts: &Options{
				readFilePath: "../testdata/format/dns.pcapng",
			},
			expectedOutFile: "../testdata/format/dns.pcapng.out",
		},
		{
			name: "udp dns -q",
			opts: &Options{
				readFilePath: "../testdata/format/dns.pcapng",
				quiet:        true,
			},
			expectedOutFile: "../testdata/format/dns.pcapng.-q.out",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := bytes.Buffer{}
			tt.opts.stdout = &output

			err := read(context.TODO(), tt.opts)
			assert.NoError(t, err)

			expected, err := os.ReadFile(tt.expectedOutFile)
			assert.NoError(t, err)
			assert.Equal(t, string(expected), output.String())
		})
	}
}
