package eip3009

import (
	"crypto/rand"

	"github.com/ethereum/go-ethereum/common"
)

func RandomNonce() (common.Hash, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(bytes[:]), nil
}
