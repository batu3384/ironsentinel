package util

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

func NewID(prefix string) string {
	var bytes [6]byte
	_, _ = rand.Read(bytes[:])
	return prefix + "-" + time.Now().UTC().Format("20060102T150405") + "-" + hex.EncodeToString(bytes[:])
}
