package cmd

import (
	"bytes"
	"context"
	"github.com/stretchr/testify/assert"
	"os"
	"path"
	"strings"
	"testing"
)

func TestFormat(t *testing.T) {
	type args struct {
		name              string
		opts              *Options
		expectedOutFile   string
		expectedWriteFile string
	}

	tests := []args{
		{
			name: "tcp",
			opts: &Options{
				readFilePath: "../testdata/format/tcp.pcapng",
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.out.txt",
		},
		{
			name: "tcp -w x.json",
			opts: &Options{
				readFilePath: "../testdata/format/tcp.pcapng",
			},
			expectedOutFile:   "../testdata/format/tcp.pcapng.out.txt",
			expectedWriteFile: "../testdata/format/tcp.pcapng.out.json",
		},
		{
			name: "pcapng file detect",
			opts: &Options{
				readFilePath: "../testdata/format/tcp.pcapng.unknown",
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.out.txt",
		},
		{
			name: "tcp -t",
			opts: &Options{
				readFilePath:   "../testdata/format/tcp.pcapng",
				printTimestamp: 1,
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-t.out.txt",
		},
		{
			name: "tcp -tt",
			opts: &Options{
				readFilePath:   "../testdata/format/tcp.pcapng",
				printTimestamp: 2,
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-tt.out.txt",
		},
		{
			name: "tcp -tt --time-stamp-precision=nano",
			opts: &Options{
				readFilePath:       "../testdata/format/tcp.pcapng",
				printTimestamp:     2,
				timeStampPrecision: "nano",
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-tt.nano.out.txt",
		},
		{
			name: "tcp -ttt",
			opts: &Options{
				readFilePath:   "../testdata/format/tcp.pcapng",
				printTimestamp: 3,
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-ttt.out.txt",
		},
		{
			name: "tcp -ttt --time-stamp-precision=nano",
			opts: &Options{
				readFilePath:       "../testdata/format/tcp.pcapng",
				printTimestamp:     3,
				timeStampPrecision: "nano",
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-ttt.nano.out.txt",
		},
		{
			name: "tcp -tttt",
			opts: &Options{
				readFilePath:   "../testdata/format/tcp.pcapng",
				printTimestamp: 4,
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-tttt.out.txt",
		},
		{
			name: "tcp -tttt --time-stamp-precision=nano",
			opts: &Options{
				readFilePath:       "../testdata/format/tcp.pcapng",
				printTimestamp:     4,
				timeStampPrecision: "nano",
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-tttt.nano.out.txt",
		},
		{
			name: "tcp -ttttt",
			opts: &Options{
				readFilePath:   "../testdata/format/tcp.pcapng",
				printTimestamp: 5,
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-ttttt.out.txt",
		},
		{
			name: "tcp -ttttt --time-stamp-precision=nano",
			opts: &Options{
				readFilePath:       "../testdata/format/tcp.pcapng",
				printTimestamp:     5,
				timeStampPrecision: "nano",
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-ttttt.nano.out.txt",
		},
		{
			name: "tcp -c",
			opts: &Options{
				readFilePath:   "../testdata/format/tcp.pcapng",
				maxPacketCount: 2,
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-c.out.txt",
		},
		{
			name: "tcp -v",
			opts: &Options{
				readFilePath: "../testdata/format/tcp.pcapng",
				verbose:      1,
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-v.out.txt",
		},
		{
			name: "tcp -v --context=process",
			opts: &Options{
				readFilePath:     "../testdata/format/tcp.pcapng",
				verbose:          1,
				enhancedContexts: []string{contextProcess},
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-v.--context.process.out.txt",
		},
		{
			name: "tcp -q",
			opts: &Options{
				readFilePath: "../testdata/format/tcp.pcapng",
				quiet:        true,
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-q.out.txt",
		},
		{
			name: "tcp -A",
			opts: &Options{
				readFilePath:     "../testdata/format/tcp.pcapng",
				printDataAsASCII: true,
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-A.out.txt",
		},
		{
			name: "tcp -x",
			opts: &Options{
				readFilePath:   "../testdata/format/tcp.pcapng",
				printDataAsHex: 1,
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-x.out.txt",
		},
		{
			name: "tcp -xx",
			opts: &Options{
				readFilePath:   "../testdata/format/tcp.pcapng",
				printDataAsHex: 2,
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-xx.out.txt",
		},
		{
			name: "tcp -X",
			opts: &Options{
				readFilePath:        "../testdata/format/tcp.pcapng",
				printDataAsHexASCII: 1,
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-X.out.txt",
		},
		{
			name: "tcp -XX",
			opts: &Options{
				readFilePath:        "../testdata/format/tcp.pcapng",
				printDataAsHexASCII: 2,
			},
			expectedOutFile: "../testdata/format/tcp.pcapng.-XX.out.txt",
		},
		{
			name: "mptcp",
			opts: &Options{
				readFilePath: "../testdata/format/mptcp.pcap",
			},
			expectedOutFile: "../testdata/format/mptcp.pcap.out.txt",
		},
		{
			name: "tfo and sack",
			opts: &Options{
				readFilePath: "../testdata/format/tfo.pcap",
			},
			expectedOutFile: "../testdata/format/tfo.pcap.out.txt",
		},
		{
			name: "udp",
			opts: &Options{
				readFilePath: "../testdata/format/udp.pcap",
			},
			expectedOutFile: "../testdata/format/udp.pcap.out.txt",
		},
		{
			name: "udp -w x.json",
			opts: &Options{
				readFilePath: "../testdata/format/udp.pcap",
			},
			expectedOutFile:   "../testdata/format/udp.pcap.out.txt",
			expectedWriteFile: "../testdata/format/udp.pcap.out.json",
		},
		{
			name: "pcap file detect",
			opts: &Options{
				readFilePath: "../testdata/format/udp.pcap.unknown",
			},
			expectedOutFile: "../testdata/format/udp.pcap.out.txt",
		},
		{
			name: "udp dns",
			opts: &Options{
				readFilePath: "../testdata/format/dns.pcapng",
			},
			expectedOutFile: "../testdata/format/dns.pcapng.out.txt",
		},
		{
			name: "udp dns -q",
			opts: &Options{
				readFilePath: "../testdata/format/dns.pcapng",
				quiet:        true,
			},
			expectedOutFile: "../testdata/format/dns.pcapng.-q.out.txt",
		},
		{
			name: "arp",
			opts: &Options{
				readFilePath: "../testdata/format/arp.pcapng",
			},
			expectedOutFile: "../testdata/format/arp.pcapng.out.txt",
		},
		{
			name: "arp -w x.json",
			opts: &Options{
				readFilePath: "../testdata/format/arp.pcapng",
			},
			expectedOutFile:   "../testdata/format/arp.pcapng.out.txt",
			expectedWriteFile: "../testdata/format/arp.pcapng.out.json",
		},
		{
			name: "icmp",
			opts: &Options{
				readFilePath: "../testdata/format/icmp.pcapng",
			},
			expectedOutFile: "../testdata/format/icmp.pcapng.out.txt",
		},
		{
			name: "icmp -w x.json",
			opts: &Options{
				readFilePath: "../testdata/format/icmp.pcapng",
			},
			expectedOutFile:   "../testdata/format/icmp.pcapng.out.txt",
			expectedWriteFile: "../testdata/format/icmp.pcapng.out.json",
		},
		{
			name: "thread",
			opts: &Options{
				readFilePath: "../testdata/format/curl-thread.pcapng",
			},
			expectedOutFile: "../testdata/format/curl-thread.pcapng.out.txt",
		},
		{
			name: "thread -v",
			opts: &Options{
				readFilePath: "../testdata/format/curl-thread.pcapng",
				verbose:      1,
			},
			expectedOutFile: "../testdata/format/curl-thread.pcapng.-v.out.txt",
		},
		{
			name: "user",
			opts: &Options{
				readFilePath: "../testdata/format/curl-user.pcapng",
			},
			expectedOutFile: "../testdata/format/curl-user.pcapng.out.txt",
		},
		{
			name: "user -v",
			opts: &Options{
				readFilePath: "../testdata/format/curl-user.pcapng",
				verbose:      1,
			},
			expectedOutFile: "../testdata/format/curl-user.pcapng.-v.out.txt",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := bytes.Buffer{}
			tt.opts.stdout = &output

			if tt.expectedWriteFile != "" {
				wf, err := os.MkdirTemp(os.TempDir(), "test-ptcpdump")
				assert.NoError(t, err)
				p := path.Join(wf, "test.json")
				defer os.Remove(p)
				tt.opts.writeFilePath = p
			}

			err := prepareOptions(tt.opts, nil, nil)
			assert.NoError(t, err)

			err = read(context.TODO(), tt.opts)
			assert.NoError(t, err)

			expected, err := os.ReadFile(tt.expectedOutFile)
			assert.NoError(t, err)
			assert.Equal(t, string(expected), output.String())

			if tt.expectedWriteFile != "" {
				expected, err := os.ReadFile(tt.expectedWriteFile)
				assert.NoError(t, err)
				actual, err := os.ReadFile(tt.opts.writeFilePath)
				assert.NoError(t, err)
				assert.Equal(t, strings.TrimSpace(string(expected)), strings.TrimSpace(string(actual)))
			}

		})
	}
}
