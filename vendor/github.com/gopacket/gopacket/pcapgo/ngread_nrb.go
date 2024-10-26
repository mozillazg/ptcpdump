// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
// author: Raphael Coeffic <raphael.coeffic@frafos.com>

package pcapgo

import (
	"bytes"
	"fmt"
	"net/netip"
)

type nameRecordHeader struct {
	recordType   uint16
	recordLength uint16
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func paddingBytes32b(length int) int {
	padding := length % 4
	if padding > 0 {
		padding = 4 - padding
	}
	return padding
}

func newIPAddress(data []byte) *NgIPAddress {
	addr := &NgIPAddress{}
	addr.Addr, _ = netip.AddrFromSlice(data)
	return addr
}

func newHWAddress(data []byte) *NgEUIAddress {
	addr := &NgEUIAddress{}
	addr.Addr = bytes.Clone(data)
	return addr
}

func (r *NgReader) readIPAddr(nr *NgNameRecord, length int) error {
	if err := r.readBytes(r.buf[:length]); err != nil {
		return fmt.Errorf("could not read IP address: %v", err)
	}
	nr.Addr = newIPAddress(r.buf[:length])
	return nil
}

func (r *NgReader) readHWAddr(nr *NgNameRecord, length int) error {
	if err := r.readBytes(r.buf[:length]); err != nil {
		return fmt.Errorf("could not read EUI address: %v", err)
	}
	nr.Addr = newHWAddress(r.buf[:])
	return nil
}

func (r *NgReader) discard(length int) error {
	if _, err := r.r.Discard(length); err != nil {
		return fmt.Errorf("could not discard %d bytes: %v", length, err)
	}
	r.currentBlock.length -= uint32(length)
	return nil
}

func (r *NgReader) readNameResolutionBlock() error {

	for r.currentBlock.length > 0 {
		// Read name record header
		if err := r.readBytes(r.buf[:4]); err != nil {
			return fmt.Errorf("could not read NameRecord Header block length: %v", err)
		}
		r.currentBlock.length -= 4

		var nrh = &nameRecordHeader{}
		nrh.recordType = r.getUint16(r.buf[0:2])
		nrh.recordLength = r.getUint16(r.buf[2:4])

		var nameRecord = NgNameRecord{}
		length := min(int(nrh.recordLength), int(r.currentBlock.length))
		padding := paddingBytes32b(length)

		switch nrh.recordType {
		case ngNameRecordIPv4:
			if err := r.readIPAddr(&nameRecord, 4); err != nil {
				return fmt.Errorf("could not read IPv4 address: %v", err)
			}
		case ngNameRecordIPv6:
			if err := r.readIPAddr(&nameRecord, 16); err != nil {
				return fmt.Errorf("could not read IPv6 address: %v", err)
			}
		case ngNameRecordEUI48:
			if err := r.readHWAddr(&nameRecord, 6); err != nil {
				return fmt.Errorf("could not read EUI-48 address: %v", err)
			}
		case ngNameRecordEUI64:
			if err := r.readHWAddr(&nameRecord, 8); err != nil {
				return fmt.Errorf("could not read EUI-64 address: %v", err)
			}
		case ngNameRecordEnd:
			goto DONE
		default:
			// discard record length
			if err := r.discard(length + padding); err != nil {
				return fmt.Errorf("could not discard unknown name record: %v", err)
			}
			continue
		}
		r.currentBlock.length -= uint32(length)
		length -= nameRecord.Addr.Len()

		for length > 0 {
			bstr, err := r.r.ReadBytes(0)
			if err != nil {
				return fmt.Errorf("could not read name: %v", err)
			}
			length -= len(bstr)
			name := string(bytes.Trim(bstr, "\x00"))
			nameRecord.Names = append(nameRecord.Names, name)
		}
		r.nameRecords = append(r.nameRecords, nameRecord)

		//consume padding
		if err := r.discard(padding); err != nil {
			return err
		}
	}

DONE:
	// discard everything after 'nrb_record_end' (including options)
	return r.discard(int(r.currentBlock.length))
}
