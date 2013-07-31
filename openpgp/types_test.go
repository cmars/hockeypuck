package openpgp

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVisitor(t *testing.T) {
	key := MustInputAscKey(t, "sksdigest.asc")
	t.Log(key.userIds[0].signatures[0])
	var npub, nuid, nsub, nsig int
	key.Visit(func(rec PacketRecord) error {
		switch rec.(type) {
		case *Pubkey:
			npub++
		case *UserId:
			nuid++
		case *Subkey:
			nsub++
		case *Signature:
			nsig++
		}
		return nil
	})
	assert.Equal(t, 1, npub)
	assert.Equal(t, 1, nuid)
	assert.Equal(t, 1, nsub)
	assert.Equal(t, 2, nsig)
}

func TestIterOpaque(t *testing.T) {
	key := MustInputAscKey(t, "sksdigest.asc")
	hits := make(map[int]int)
	for _, tag := range []int{2, 6, 13, 14} {
		hits[tag] = 0
	}
	for opkt := range IterOpaquePackets(key) {
		assert.Nil(t, opkt.Error)
		hits[int(opkt.Tag)]++
	}
	t.Log(hits)
	assert.Equal(t, 2, hits[2])
	assert.Equal(t, 1, hits[6])
	assert.Equal(t, 1, hits[13])
	assert.Equal(t, 1, hits[14])
	assert.Equal(t, 4, len(hits))
}
