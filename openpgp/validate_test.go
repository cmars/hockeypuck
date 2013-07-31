package openpgp

import (
	"testing"
)

func TestBadSelfSigUid(t *testing.T) {
	key := MustInputAscKey(t, "badselfsig.asc")
	kv := ValidateKey(key)
	t.Log(kv)
}

/*
	armorBlock, err := armor.Decode(bytes.NewBufferString(armoredKey))
	assert.Equal(t, nil, err)
	keyChan, errChan := ReadValidKeys(armorBlock.Body)
READING:
	for {
		select {
		case key, ok := <-keyChan:
			if !ok {
				break READING
			}
			t.Errorf("Should not get a key %v -- it's not valid", key)
		case err, ok := <-errChan:
			if !ok {
				break READING
			}
			t.Log(err)
		}
	}
}
*/
