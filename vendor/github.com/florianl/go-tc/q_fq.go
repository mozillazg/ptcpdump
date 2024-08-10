package tc

import (
	"fmt"

	"github.com/mdlayher/netlink"
)

const (
	tcaFqUnspec = iota
	tcaFqPLimit
	tcaFqFlowPLimit
	tcaFqQuantum
	tcaFqInitQuantum
	tcaFqRateEnable
	tcaFqFlowDefaultRate
	tcaFqFlowMaxRate
	tcaFqBucketsLog
	tcaFqFlowRefillDelay
	tcaFqOrphanMask
	tcaFqLowRateThreshold
	tcaFqCEThreshold
)

// Fq contains attributes of the fq discipline
type Fq struct {
	PLimit           *uint32
	FlowPLimit       *uint32
	Quantum          *uint32
	InitQuantum      *uint32
	RateEnable       *uint32
	FlowDefaultRate  *uint32
	FlowMaxRate      *uint32
	BucketsLog       *uint32
	FlowRefillDelay  *uint32
	OrphanMask       *uint32
	LowRateThreshold *uint32
	CEThreshold      *uint32
}

// unmarshalFq parses the Fq-encoded data and stores the result in the value pointed to by info.
func unmarshalFq(data []byte, info *Fq) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case tcaFqPLimit:
			info.PLimit = uint32Ptr(ad.Uint32())
		case tcaFqFlowPLimit:
			info.FlowPLimit = uint32Ptr(ad.Uint32())
		case tcaFqQuantum:
			info.Quantum = uint32Ptr(ad.Uint32())
		case tcaFqInitQuantum:
			info.InitQuantum = uint32Ptr(ad.Uint32())
		case tcaFqRateEnable:
			info.RateEnable = uint32Ptr(ad.Uint32())
		case tcaFqFlowDefaultRate:
			info.FlowDefaultRate = uint32Ptr(ad.Uint32())
		case tcaFqFlowMaxRate:
			info.FlowMaxRate = uint32Ptr(ad.Uint32())
		case tcaFqBucketsLog:
			info.BucketsLog = uint32Ptr(ad.Uint32())
		case tcaFqFlowRefillDelay:
			info.FlowRefillDelay = uint32Ptr(ad.Uint32())
		case tcaFqOrphanMask:
			info.OrphanMask = uint32Ptr(ad.Uint32())
		case tcaFqLowRateThreshold:
			info.LowRateThreshold = uint32Ptr(ad.Uint32())
		case tcaFqCEThreshold:
			info.CEThreshold = uint32Ptr(ad.Uint32())
		default:
			return fmt.Errorf("unmarshalFq()\t%d\n\t%v", ad.Type(), ad.Bytes())
		}
	}
	return ad.Err()
}

// marshalFq returns the binary encoding of Fq
func marshalFq(info *Fq) ([]byte, error) {
	options := []tcOption{}

	if info == nil {
		return []byte{}, fmt.Errorf("Fq: %w", ErrNoArg)
	}

	// TODO: improve logic and check combinations
	if info.PLimit != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqPLimit, Data: uint32Value(info.PLimit)})
	}
	if info.FlowPLimit != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqFlowPLimit, Data: uint32Value(info.FlowPLimit)})
	}
	if info.Quantum != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqQuantum, Data: uint32Value(info.Quantum)})
	}
	if info.InitQuantum != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqInitQuantum, Data: uint32Value(info.InitQuantum)})
	}
	if info.RateEnable != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqRateEnable, Data: uint32Value(info.RateEnable)})
	}
	if info.FlowDefaultRate != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqFlowDefaultRate, Data: uint32Value(info.FlowDefaultRate)})
	}
	if info.FlowMaxRate != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqFlowMaxRate, Data: uint32Value(info.FlowMaxRate)})
	}
	if info.BucketsLog != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqBucketsLog, Data: uint32Value(info.BucketsLog)})
	}
	if info.FlowRefillDelay != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqFlowRefillDelay, Data: uint32Value(info.FlowRefillDelay)})
	}
	if info.OrphanMask != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqOrphanMask, Data: uint32Value(info.OrphanMask)})
	}
	if info.LowRateThreshold != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqLowRateThreshold, Data: uint32Value(info.LowRateThreshold)})
	}
	if info.CEThreshold != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqCEThreshold, Data: uint32Value(info.CEThreshold)})
	}
	return marshalAttributes(options)
}
