package tc

import (
	"fmt"

	"github.com/mdlayher/netlink"
)

const (
	tcaGredUnspec = iota
	tcaGredParms
	tcaGredStab
	tcaGredDPS
	tcaGredMaxP
	tcaGredLimit
	tcaGredVqList /* nested TCA_GRED_VQ_ENTRY */
)

type GredQOpt struct {
	Limit    uint32 /* HARD maximal queue length (bytes)    */
	QthMin   uint32 /* Min average length threshold (bytes) */
	QthMax   uint32 /* Max average length threshold (bytes) */
	DP       uint32 /* up to 2^32 DPs */
	Backlog  uint32
	Qave     uint32
	Forced   uint32
	Early    uint32
	Other    uint32
	Pdrop    uint32
	Wlog     uint8 /* log(W)               */
	Plog     uint8 /* log(P_max/(qth_max-qth_min)) */
	ScellLog uint8 /* cell size for idle damping */
	Prio     uint8 /* prio of this VQ */
	Packets  uint32
	ByteSin  uint32
}

type GredSOpt struct {
	DPs   uint32
	DefDP uint32
	Grio  uint8
	Flags uint8
	Pad   uint16
}

// Gred contains attributes of the etf discipline
type Gred struct {
	Parms *GredQOpt
	DPS   *GredSOpt
	MaxP  *uint32
	Limit *uint32
}

// unmarshalGred parses the Gred-encoded data and stores the result in the value pointed to by info.
func unmarshalGred(data []byte, info *Gred) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	var multiError error
	for ad.Next() {
		switch ad.Type() {
		case tcaGredParms:
			opt := &GredQOpt{}
			err := unmarshalStruct(ad.Bytes(), opt)
			multiError = concatError(multiError, err)
			info.Parms = opt
		case tcaGredDPS:
			opt := &GredSOpt{}
			err := unmarshalStruct(ad.Bytes(), opt)
			multiError = concatError(multiError, err)
			info.DPS = opt
		case tcaGredMaxP:
			info.MaxP = uint32Ptr(ad.Uint32())
		case tcaGredLimit:
			info.Limit = uint32Ptr(ad.Uint32())
		default:
			return fmt.Errorf("unmarshalGred()\t%d\n\t%v", ad.Type(), ad.Bytes())
		}
	}
	return concatError(multiError, ad.Err())
}

// marshalGred returns the binary encoding of Gred
func marshalGred(info *Gred) ([]byte, error) {
	options := []tcOption{}

	if info == nil {
		return []byte{}, fmt.Errorf("Gred: %w", ErrNoArg)
	}

	// TODO: improve logic and check combinations
	var multiError error
	if info.Parms != nil {
		data, err := marshalStruct(info.Parms)
		multiError = concatError(multiError, err)
		options = append(options, tcOption{Interpretation: vtBytes, Type: tcaGredParms, Data: data})
	}
	if info.DPS != nil {
		data, err := marshalStruct(info.DPS)
		multiError = concatError(multiError, err)
		options = append(options, tcOption{Interpretation: vtBytes, Type: tcaGredDPS, Data: data})
	}
	if info.MaxP != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaGredMaxP, Data: uint32Value(info.MaxP)})
	}
	if info.Limit != nil {
		options = append(options, tcOption{Interpretation: vtUint32, Type: tcaGredLimit, Data: uint32Value(info.Limit)})
	}
	if multiError != nil {
		return []byte{}, multiError
	}
	return marshalAttributes(options)

}
