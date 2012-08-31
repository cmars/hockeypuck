/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012  Casey Marshall

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package mgo

import (
	"bytes"
	"flag"
	"strings"
	"testing"
	"github.com/bmizerany/assert"
	"launchpad.net/hockeypuck"
	"bitbucket.org/cmars/go.crypto/openpgp/armor"
)

var mgoServer *string = flag.String("server", "localhost", "mongo server")

func createWorker(t *testing.T) *MgoWorker {
	worker, err := NewWorker(nil, *mgoServer)
	assert.Equal(t, err, nil)
	worker.c.DropCollection()
	assert.Equal(t, err, nil)
	worker.session.Close()
	worker, err = NewWorker(nil, *mgoServer)
	assert.Equal(t, err, nil)
	return worker
}

func normalizeArmoredKey(t *testing.T, armoredKey string) string {
	armorBlock, err := armor.Decode(bytes.NewBufferString(armoredKey))
	assert.Equal(t, err, nil)
	keyChan, errorChan := readKeys(armorBlock.Body)
	out := bytes.NewBuffer([]byte{})
	for {
		select {
		case key, moreKeys :=<-keyChan:
			if key != nil {
				err = writeKey(out, key)
				assert.Equal(t, err, nil)
			}
			if !moreKeys {
				return string(out.Bytes())
			}
		case err, has :=<-errorChan:
			if has {
				assert.Equal(t, err, nil)  // not likely...
			}
		}
	}
	panic("should not get here")
}

// Add a key.
// Get that key by short, long id and full fingerprint.
// Find key by fulltext search.
func TestAddGetFind(t *testing.T) {
	worker := createWorker(t)
	// Lookup key by fingerprint. Hasn't been added yet, shouldn't be found
	key, err := worker.lookupKey("10fe8cf1b483f7525039aa2a361bc1f023e0dcca")
	assert.Equalf(t, hockeypuck.KeyNotFound, err, "lookup should have failed, haven't added yet")
	err = worker.AddKey(aliceUnsigned)
	assert.Equal(t, err, nil)
	key, err = worker.lookupKey("10fe8cf1b483f7525039aa2a361bc1f023e0dcca")
	assert.Equal(t, err, nil)
	assert.Equal(t, key.Fingerprint, "10fe8cf1b483f7525039aa2a361bc1f023e0dcca")
	expectKey := normalizeArmoredKey(t, aliceUnsigned)
	// Lookups with full fingerprint, 8-byte long and 4-byte short key ID
	for _, keyid := range []string{
			"10fe8cf1b483f7525039aa2a361bc1f023e0dcca",
			"361bc1f023e0DCCA",
			"23e0DCCA"} {
		armor, err := worker.GetKey(keyid)
		assert.Equalf(t, err, nil, "Lookup with keyid=%v", keyid)
		assert.Equalf(t, armor, expectKey, "Lookup with keyid=%v", keyid)
		keyid = strings.ToUpper(keyid)
		armor, err = worker.GetKey(keyid)
		assert.Equalf(t, err, nil, "Lookup with keyid=%v", keyid)
		assert.Equalf(t, armor, expectKey, "Lookup with keyid=%v", keyid)
	}
	// Invalid key IDs
	for _, keyid := range []string{"asdf", "a5", ""} {
		_, err = worker.GetKey("a5")
		assert.Tf(t, err == hockeypuck.InvalidKeyId, "Lookup with keyid=%v", keyid)
	}
/*
	// Full-text lookups
	pubKey, err := worker.lookupKey("10fe8cf1b483f7525039aa2a361bc1f023e0dcca")
	assert.Equal(t, err, nil)
	for _, search := range []string{"alice", "alice@example.com"} {
		uuids, err := worker.FindKeys(search)
		assert.Equal(t, err, nil)
		assert.Equalf(t, 1, len(uuids), "Full-text search on: %v", search)
		assert.Equal(t, kr.uuid, uuids[0])
	}
*/
}

// Add a key.
// Then add a new revision of it with a signature added.
func TestUpdateKey(t *testing.T) {
	worker := createWorker(t)
	// Put an unsigned key
	unsignedKey := normalizeArmoredKey(t, aliceUnsigned)
	err := worker.AddKey(unsignedKey)
	assert.Equal(t, err, nil)
	last, err := worker.lookupKey("10fe8cf1b483f7525039aa2a361bc1f023e0dcca")
	assert.Equal(t, err, nil)
	assert.T(t, last != nil)
	assert.Equal(t, "alice <alice@example.com>", last.Identities[0].Id)
	assert.Equal(t, 1, len(last.Identities[0].Signatures))
	// Put the key with signature added
	signedKey := normalizeArmoredKey(t, aliceSigned)
	err = worker.AddKey(signedKey)
	assert.Equal(t, err, nil)
	// Get the now-updated key
	last, err = worker.lookupKey("10fe8cf1b483f7525039aa2a361bc1f023e0dcca")
	assert.Equal(t, err, nil)
	assert.T(t, last != nil)
	assert.Equal(t, "alice <alice@example.com>", last.Identities[0].Id)
	assert.Equal(t, 2, len(last.Identities[0].Signatures))
	// Put a now out-of-date version of the key (without the added signature)
	// It should update with a merged keyring, but not overwrite the key
	err = worker.AddKey(unsignedKey)
	last, err = worker.lookupKey("10fe8cf1b483f7525039aa2a361bc1f023e0dcca")
	assert.Equal(t, err, nil)
	assert.T(t, last != nil)
	assert.Equal(t, "alice <alice@example.com>", last.Identities[0].Id)
	assert.Equal(t, 2, len(last.Identities[0].Signatures))
}

const aliceUnsigned = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.11 (GNU/Linux)

mQENBFA0ErkBCAC2i7SefWM5DcffFH2LJ5aqt2zJfcwqd5a1S9RzAkb4THRNXhnc
BkiK1LawKhYUZVOVXMRcPCHsjXdBRGoyqK3kgFQh9Li7D03pRnNhedKMK/pnHeXX
kiofA4O7HI3EbQFz5DyCy//wjtfK20vxq43H9uulDSrNoAN67l2ivPFdKlv+r/yv
j4QOu/Z2zkJtOOpGWauBHaqq/RaMLv78O3WTXTH7NTlNfTqZ/XKdK6JdBMAtg5Ab
0Gd7LT3NxnUZ8UtGXQQvnSVzZBzJTxaOCLEKl/ES1jiBZhty6PpPrCKf6r/YL5g3
uIQ50zWtRrDzgPLiJGJnL25KHRS1GI4fl7gzABEBAAG0GWFsaWNlIDxhbGljZUBl
eGFtcGxlLmNvbT6JATgEEwECACIFAlA0ErkCGwMGCwkIBwMCBhUIAgkKCwQWAgMB
Ah4BAheAAAoJEDYbwfAj4NzKTw4H/A7l6lctrcoo4iTGwZlYzq5a2bXSJEYZ7/KK
n9mCb3aiWoM5KuHAe1oxmmDSVGPDn8BKPsI8MX4HMgFgUhxZchlJWL6cAtAbl6FW
9TigtpImt+F0MI3cGVuo3pXplpPg8DduJYixUbpPTmizY1l1nwGXBjPxldf1HbM8
IKNg4gBB5AhP7miZaW2xv+mF5+x/1K5+oIryFg0EOfLI+S2L4sTmKWnihEeOUnt4
WR6OoSpCCqYXKDNJGXJfFvJ7WqMA3A710E+fwnPXhEdWgNwVQThcJGCjQG6O1hGh
BU7YsLiXyStTAP7gke8UzCHWwGD7KSYtlhveWbvWgMlrhQtFCaC5AQ0EUDQSuQEI
AOT1AhLb3k6FEp7Yyjk7FcLlKOxIccDF8IUQ//j15vvli5OGq/jC/Y3qT5pwrUMm
1PYNeuSYj7OyDLNI+rvFFbTiiG8XFv1bjlTeg+XOoCto7CymcYl7JVpxN6SRpxhp
eKzGCzQAnAsQaSb6GwmCvvIsVR6bO/tZLG6Db6NZkgHbgrDhgE61kLsjk4lOxIFy
bxySa9TDSnEVdueXk/nj98SxMKWxoy26AYgFkgeH7Vd8zT6dydBsxZM8OB+azk30
nncw4isOAPnBDxho96ZenM6V6BBB2IuXflSsU+pFQO8EC8oUA7RBvVDUtqVc+zWm
xk27VuWOWiofvjLYNDd89D8AEQEAAYkBHwQYAQIACQUCUDQSuQIbDAAKCRA2G8Hw
I+Dcys3QCACdzDc/myqXvVfCDrF1MUq/TPLdR8PRuYgSBeECJ0P1CYqWsdIL6B/3
xgRVJhnkE+WLGgLP0igwsjOB+LaP0U5HQiR6YoQuI+zQB7CT9phSCyGByAiZanLV
HPMGNbTfIrkTdqbmCY4zPHUeAtOjNvO2NNEJPaJ6QV2SR9NQb42yDEVLusg9OYhQ
oPiJ5/rqHzL0Lkarc1EFl5Q2r1HNVIDRzGqh6YaXYzpBBdENRwlgBmZfrpzuehYE
7RCS1NvFBVYOVH27ZWSp9eBWrEIKxW87Tu1abSyHW0sL/EI4fxXUNonwteXlIZC2
JYq1f3tcdPHdcDHDIjlL+Av5mwQ/YOTx
=2nAi
-----END PGP PUBLIC KEY BLOCK-----`

const aliceSigned = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.11 (GNU/Linux)

mQENBFA0ErkBCAC2i7SefWM5DcffFH2LJ5aqt2zJfcwqd5a1S9RzAkb4THRNXhnc
BkiK1LawKhYUZVOVXMRcPCHsjXdBRGoyqK3kgFQh9Li7D03pRnNhedKMK/pnHeXX
kiofA4O7HI3EbQFz5DyCy//wjtfK20vxq43H9uulDSrNoAN67l2ivPFdKlv+r/yv
j4QOu/Z2zkJtOOpGWauBHaqq/RaMLv78O3WTXTH7NTlNfTqZ/XKdK6JdBMAtg5Ab
0Gd7LT3NxnUZ8UtGXQQvnSVzZBzJTxaOCLEKl/ES1jiBZhty6PpPrCKf6r/YL5g3
uIQ50zWtRrDzgPLiJGJnL25KHRS1GI4fl7gzABEBAAG0GWFsaWNlIDxhbGljZUBl
eGFtcGxlLmNvbT6JATgEEwECACIFAlA0ErkCGwMGCwkIBwMCBhUIAgkKCwQWAgMB
Ah4BAheAAAoJEDYbwfAj4NzKTw4H/A7l6lctrcoo4iTGwZlYzq5a2bXSJEYZ7/KK
n9mCb3aiWoM5KuHAe1oxmmDSVGPDn8BKPsI8MX4HMgFgUhxZchlJWL6cAtAbl6FW
9TigtpImt+F0MI3cGVuo3pXplpPg8DduJYixUbpPTmizY1l1nwGXBjPxldf1HbM8
IKNg4gBB5AhP7miZaW2xv+mF5+x/1K5+oIryFg0EOfLI+S2L4sTmKWnihEeOUnt4
WR6OoSpCCqYXKDNJGXJfFvJ7WqMA3A710E+fwnPXhEdWgNwVQThcJGCjQG6O1hGh
BU7YsLiXyStTAP7gke8UzCHWwGD7KSYtlhveWbvWgMlrhQtFCaCJARwEEAECAAYF
AlA0MXMACgkQYq6gHWdkD7XCdwf+NoVDf4bi3GrTw9Eb/M7PMsUpohrTKqETUltn
A/UPxH6P4+CPiAfDmdQs8xb4tLtbJs0X3cxQ+EM8iklxvqDEuSFk8tlLgSd//xUM
Pcdji4q2vyAQU9nj9iLYP5IMeNqz9jruIi61LuI0YudvbhIeWCXN1UEUYQr2OWrr
pEviFDnc1410Wq6hvV4B4NCvbjeD2L0w0MDUjqN8PkuuHkfMkWvn5liRsdSDGN8F
wEPc7c+iwTXJWBb182UVqP0uUlLsroAxPKrtfs960QRlEoDTJ3I4K/0Vco7XTu0K
peJdfAN7zifSelexhMbKsyWErpkDUwsAFa934w3nfoRQuOkvW7kBDQRQNBK5AQgA
5PUCEtveToUSntjKOTsVwuUo7EhxwMXwhRD/+PXm++WLk4ar+ML9jepPmnCtQybU
9g165JiPs7IMs0j6u8UVtOKIbxcW/VuOVN6D5c6gK2jsLKZxiXslWnE3pJGnGGl4
rMYLNACcCxBpJvobCYK+8ixVHps7+1ksboNvo1mSAduCsOGATrWQuyOTiU7EgXJv
HJJr1MNKcRV255eT+eP3xLEwpbGjLboBiAWSB4ftV3zNPp3J0GzFkzw4H5rOTfSe
dzDiKw4A+cEPGGj3pl6czpXoEEHYi5d+VKxT6kVA7wQLyhQDtEG9UNS2pVz7NabG
TbtW5Y5aKh++Mtg0N3z0PwARAQABiQEfBBgBAgAJBQJQNBK5AhsMAAoJEDYbwfAj
4NzKzdAIAJ3MNz+bKpe9V8IOsXUxSr9M8t1Hw9G5iBIF4QInQ/UJipax0gvoH/fG
BFUmGeQT5YsaAs/SKDCyM4H4to/RTkdCJHpihC4j7NAHsJP2mFILIYHICJlqctUc
8wY1tN8iuRN2puYJjjM8dR4C06M287Y00Qk9onpBXZJH01BvjbIMRUu6yD05iFCg
+Inn+uofMvQuRqtzUQWXlDavUc1UgNHMaqHphpdjOkEF0Q1HCWAGZl+unO56FgTt
EJLU28UFVg5UfbtlZKn14FasQgrFbztO7VptLIdbSwv8Qjh/FdQ2ifC15eUhkLYl
irV/e1x08d1wMcMiOUv4C/mbBD9g5PE=
=ljD+
-----END PGP PUBLIC KEY BLOCK-----`
