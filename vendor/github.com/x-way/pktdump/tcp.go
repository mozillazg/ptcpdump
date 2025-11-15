package pktdump

import "github.com/gopacket/gopacket/layers"

type tcpFlowKey struct {
	src     string
	dst     string
	srcPort layers.TCPPort
	dstPort layers.TCPPort
}

type tcpDirectionState struct {
	baseSeq        uint32
	seqInitialized bool
	seqRelative    bool
	ackRelative    bool
}

func makeTCPFlowKey(src, dst string, srcPort, dstPort layers.TCPPort) tcpFlowKey {
	return tcpFlowKey{
		src:     src,
		dst:     dst,
		srcPort: srcPort,
		dstPort: dstPort,
	}
}

func (f *Formatter) ensureTCPState(key tcpFlowKey) *tcpDirectionState {
	if state, ok := f.tcpState[key]; ok {
		return state
	}
	state := &tcpDirectionState{}
	f.tcpState[key] = state
	return state
}

func (f *Formatter) resetTCPDirection(key, reverseKey tcpFlowKey) *tcpDirectionState {
	delete(f.tcpState, reverseKey)
	state := &tcpDirectionState{}
	f.tcpState[key] = state
	return state
}
