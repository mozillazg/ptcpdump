package tc

import (
	"fmt"

	"github.com/mdlayher/netlink"
)

const (
	tcaFqPieUnspec = iota // Corresponds to similar attr struct in kernel
	tcaFqPieLimit
	tcaFqPieFlows
	tcaFqPieTarget
	tcaFqPieTUpdate
	tcaFqPieAlpha
	tcaFqPieBeta
	tcaFqPieQuantum // sch_fq_pie.c indicates 32 bit uint; kernel validates range between 1, 2^20
	tcaFqPieMemoryLimit
	tcaFqPieEcnProb
	tcaFqPieEcn
	tcaFqPieBytemode
	tcaFqPieDqRateEstimator
)

type FqPie struct {
	Limit           *uint32
	Flows           *uint32
	Target          *uint32
	TUpdate         *uint32
	Alpha           *uint32
	Beta            *uint32
	Quantum         *uint32
	MemoryLimit     *uint32
	EcnProb         *uint32
	Ecn             *uint32
	Bytemode        *uint32
	DqRateEstimator *uint32
}

// marshalFqPie returns the binary encoding of FqPie
func marshalFqPie(info *FqPie) ([]byte, error) {
	options := []tcOption{}

	if info == nil {
		return []byte{}, fmt.Errorf("FqPie: %w", ErrNoArg)
	}

	// TODO: improve logic and check combinations
	if info.Limit != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqPieLimit, Data: uint32Value(info.Limit)})
	}

	if info.Flows != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqPieFlows, Data: uint32Value(info.Flows)})
	}

	if info.Target != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqPieTarget, Data: uint32Value(info.Target)})
	}

	if info.TUpdate != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqPieTUpdate, Data: uint32Value(info.TUpdate)})
	}

	if info.Alpha != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqPieAlpha, Data: uint32Value(info.Alpha)})
	}

	if info.Beta != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqPieBeta, Data: uint32Value(info.Beta)})
	}

	if info.Quantum != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqPieQuantum, Data: uint32Value(info.Quantum)})
	}

	if info.MemoryLimit != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqPieMemoryLimit, Data: uint32Value(info.MemoryLimit)})
	}

	if info.EcnProb != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqPieEcnProb, Data: uint32Value(info.EcnProb)})
	}

	if info.Ecn != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqPieEcn, Data: uint32Value(info.Ecn)})
	}

	if info.Bytemode != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqPieBytemode, Data: uint32Value(info.Bytemode)})
	}

	if info.DqRateEstimator != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaFqPieDqRateEstimator, Data: uint32Value(info.DqRateEstimator)})
	}

	return marshalAttributes(options)
}

// unmarshalFqPie parses the FqPie-encoded data and stores the result in the value pointed to by info.
func unmarshalFqPie(data []byte, info *FqPie) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case tcaFqPieLimit:
			info.Limit = uint32Ptr(ad.Uint32())
		case tcaFqPieFlows:
			info.Flows = uint32Ptr(ad.Uint32())
		case tcaFqPieTarget:
			info.Target = uint32Ptr(ad.Uint32())
		case tcaFqPieTUpdate:
			info.TUpdate = uint32Ptr(ad.Uint32())
		case tcaFqPieAlpha:
			info.Alpha = uint32Ptr(ad.Uint32())
		case tcaFqPieBeta:
			info.Beta = uint32Ptr(ad.Uint32())
		case tcaFqPieQuantum:
			info.Quantum = uint32Ptr(ad.Uint32())
		case tcaFqPieMemoryLimit:
			info.MemoryLimit = uint32Ptr(ad.Uint32())
		case tcaFqPieEcnProb:
			info.EcnProb = uint32Ptr(ad.Uint32())
		case tcaFqPieEcn:
			info.Ecn = uint32Ptr(ad.Uint32())
		case tcaFqPieBytemode:
			info.Bytemode = uint32Ptr(ad.Uint32())
		case tcaFqPieDqRateEstimator:
			info.DqRateEstimator = uint32Ptr(ad.Uint32())
		default:
			return fmt.Errorf("unmarshalFqPie()\t%d\n\t%v", ad.Type(), ad.Bytes())
		}
	}
	return ad.Err()
}
