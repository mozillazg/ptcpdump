package gosym

import (
	"debug/elf"
	"errors"
	"fmt"
	"github.com/mozillazg/ptcpdump/internal/log"
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

const arm64InstructionLen = 4

func GetGoFuncRetOffsetsFromELF(f *elf.File, symbolName string) ([]uint64, error) {
	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}

	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}
	textSec := f.Section(".text")
	if textSec == nil {
		return nil, errors.New("no .text section")
	}

	syms = append(syms, dynsyms...)
	var symbolAddr uint64
	var symbol elf.Symbol

	for _, s := range syms {
		if s.Name != symbolName {
			continue
		}
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			// Symbol not associated with a function or other executable code.
			continue
		}

		symbolAddr = s.Value
		symbol = s
		break
	}

	start := symbolAddr - textSec.Addr
	symbolData := make([]byte, symbol.Size)
	if _, err := textSec.ReadAt(symbolData, int64(start)); err != nil {
		return nil, err
	}
	switch f.FileHeader.Machine {
	case elf.EM_X86_64:
		return findAMD64RetInstructions(symbolData)
	case elf.EM_AARCH64:
		return findARM64RetInstructions(symbolData)
	}

	return nil, fmt.Errorf("symbol %q not found", symbolName)
}

func findAMD64RetInstructions(data []byte) ([]uint64, error) {
	var retOffsets []uint64
	var cursor int
	for cursor < len(data) {
		inst, err := x86asm.Decode(data[cursor:], 64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode amd64 instruction at offset %d: %w", cursor, err)
		}

		if inst.Op == x86asm.RET {
			retOffsets = append(retOffsets, uint64(cursor))
		}

		cursor += inst.Len
	}

	return retOffsets, nil
}

func findARM64RetInstructions(data []byte) ([]uint64, error) {
	var retOffsets []uint64
	var cursor int
	for cursor < len(data) {
		inst, err := arm64asm.Decode(data[cursor:])
		if err != nil {
			cursor += arm64InstructionLen
			log.Infof("failed to decode arm64 instruction at offset %d: %s", cursor, err)
			continue
		}

		if inst.Op == arm64asm.RET {
			retOffsets = append(retOffsets, uint64(cursor))
		}

		cursor += arm64InstructionLen
	}

	return retOffsets, nil
}
