package tc

import (
	"fmt"

	"github.com/mdlayher/netlink"
)

const (
	tcaEmMetaUnspec = iota
	tcaEmMetaHdr
	tcaEmMetaLValue
	tcaEmMetaRValue
)

type MetaMatch struct {
	Hdr   *MetaHdr
	Left  *MetaValueType
	Right *MetaValueType
}

type MetaHdr struct {
	Left  MetaValue
	Right MetaValue
}

type MetaValue struct {
	Kind  uint16
	Shift uint8
	Op    uint8
}

type MetaValueType struct {
	Var *[]byte
	Int *uint32
}

func unmarshalMetaMatchValue(kind, id int, value []byte, dst **MetaValueType) error {
	switch kind {
	case 0:
		// TCF_META_TYPE_VAR
		return ErrNotImplemented
	case 1:
		// TCF_META_TYPE_INT
		if len(value) != 4 {
			return fmt.Errorf("assignValue(): unexpected length of value: %d", len(value))
		}
		*dst = &MetaValueType{
			Int: uint32Ptr(nativeEndian.Uint32(value)),
		}
	default:
		return fmt.Errorf("assignValue(): unknown value type: %d", kind)
	}
	return nil
}

func unmarshalMetaMatch(data []byte, info *MetaMatch) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	var multiError error
	var lValue, rValue []byte
	for ad.Next() {
		switch ad.Type() {
		case tcaEmMetaHdr:
			tmp := &MetaHdr{}
			err := unmarshalStruct(ad.Bytes(), tmp)
			multiError = concatError(multiError, err)
			info.Hdr = tmp
		case tcaEmMetaLValue:
			lValue = ad.Bytes()
		case tcaEmMetaRValue:
			rValue = ad.Bytes()
		default:
			return fmt.Errorf("unmarshalMetaMatch()\t%d\n\t%v", ad.Type(), ad.Bytes())
		}
	}

	if len(lValue) != 0 {
		err = unmarshalMetaMatchValue(int(info.Hdr.Left.Kind>>12), int(info.Hdr.Left.Kind&0x7ff),
			lValue, &info.Left)
		multiError = concatError(multiError, err)
	}
	if len(rValue) != 0 {
		err = unmarshalMetaMatchValue(int(info.Hdr.Right.Kind>>12), int(info.Hdr.Right.Kind&0x7ff),
			rValue, &info.Right)
		multiError = concatError(multiError, err)
	}

	return concatError(multiError, ad.Err())
}

func marshalMetaMatchValue(kind int, value *MetaValueType) ([]byte, error) {
	switch kind {
	case 0:
		// TCF_META_TYPE_VAR
		return []byte{}, ErrNotImplemented
	case 1:
		// TCF_META_TYPE_INT
		return []byte{
			byte(*value.Int),
			byte(*value.Int >> 8),
			byte(*value.Int >> 16),
			byte(*value.Int >> 24),
		}, nil

	default:
		return []byte{}, fmt.Errorf("assignValue(): unknown value type: %d", kind)
	}
}

func marshalMetaMatch(info *MetaMatch) ([]byte, error) {
	options := []tcOption{}

	if info == nil {
		return []byte{}, fmt.Errorf("MetaMatch: %w", ErrNoArg)
	}
	var multiError error

	// TODO: improve logic and check combinations
	if info.Hdr != nil {
		data, err := marshalStruct(info.Hdr)
		multiError = concatError(multiError, err)
		options = append(options, tcOption{Interpretation: vtBytes, Type: tcaEmMetaHdr, Data: data})
	} else {
		return []byte{}, fmt.Errorf("MetaMatch: missing Hdr: %w", ErrNoArg)
	}

	if info.Left != nil {
		data, err := marshalMetaMatchValue(int(info.Hdr.Left.Kind>>12), info.Left)
		multiError = concatError(multiError, err)
		options = append(options, tcOption{Interpretation: vtBytes, Type: tcaEmMetaLValue, Data: data})
	}

	if info.Right != nil {
		data, err := marshalMetaMatchValue(int(info.Hdr.Right.Kind>>12), info.Right)
		multiError = concatError(multiError, err)
		options = append(options, tcOption{Interpretation: vtBytes, Type: tcaEmMetaRValue, Data: data})
	}

	if multiError != nil {
		return []byte{}, multiError
	}

	return marshalAttributes(options)
}
