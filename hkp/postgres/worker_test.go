/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2014  Casey Marshall

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

package openpgp

import "fmt"

func connectString() string {
	return fmt.Sprintf(
		"dbname=postgres host=/var/run/postgresql sslmode=disable user=%s", currentUsername())
}

/*
func MustCreateWorker(t *testing.T) *Worker {
	db, err := sqlx.Connect("postgres", connectString())
	assert.Nil(t, err)
	Execf(db, "DROP DATABASE IF EXISTS testhkp")
	Execf(db, "CREATE DATABASE testhkp")
	hockeypuck.SetConfig(fmt.Sprintf(`
[hockeypuck.openpgp.db]
driver="postgres"
dsn="dbname=testhkp host=/var/run/postgresql sslmode=disable user=%s"
`, currentUsername()))
	w, err := NewWorker(nil, nil)
	assert.Nil(t, err)
	return w
}

func MustDestroyWorker(t *testing.T, w *Worker) {
	w.db.Close()
	db, err := sqlx.Connect("postgres", connectString())
	assert.Nil(t, err)
	db.Close()
}

func TestValidateKey(t *testing.T) {
	f := MustInput(t, "tails.asc")
	defer f.Close()
	block, err := armor.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	var keys []*Pubkey
	for keyRead := range ReadKeys(block.Body) {
		keys = append(keys, keyRead.Pubkey)
	}
	assert.Equal(t, 1, len(keys))
	assert.Equal(t, 2, len(keys[0].userIds))
	for i := 0; i < 2; i++ {
		assert.NotEmpty(t, keys[0].userIds[i].ScopedDigest)
	}
}

func TestRoundTripKeys(t *testing.T) {
	for _, testfile := range []string{
		"sksdigest.asc", "alice_signed.asc", "alice_unsigned.asc",
		"uat.asc", "tails.asc", "fece664e.asc", "weasel.asc",
		"rtt-140.asc"} {
		testRoundTripKey(t, testfile)
	}
}

func testRoundTripKey(t *testing.T, testfile string) {
	w := MustCreateWorker(t)
	defer MustDestroyWorker(t, w)
	srckey1 := MustInputAscKey(t, testfile)
	err := w.InsertKey(srckey1)
	assert.Nil(t, err)
	fetchkey2, err := w.FetchKey(srckey1.RFingerprint)
	if err != nil {
		t.Fatalf("%s: %v", testfile, err)
	}
	h1 := SksDigest(srckey1, md5.New())
	h2 := SksDigest(fetchkey2, md5.New())
	assert.Equal(t, h1, h2, "file: %v", testfile)
	assert.Equal(t, srckey1.Md5, h1, "file: %v", testfile)
	assert.Equal(t, fetchkey2.Md5, h2, "file: %v", testfile)
}

func testReadDigestDups(t *testing.T, testfile string) {
	f := MustInput(t, "rtt-140.asc")
	defer f.Close()
	block, err := armor.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	var opkr *OpaqueKeyring
	for kr := range ReadOpaqueKeyrings(block.Body) {
		if opkr != nil {
			t.Fatal("unexpected keyring")
		}
		opkr = kr
	}
	assert.Equal(t, len(opkr.Packets), 24)

	pubkey, err := opkr.Parse()
	assert.Nil(t, err)
	var buf bytes.Buffer
	err = WritePackets(&buf, pubkey)
	assert.Nil(t, err)
	opkr = nil
	for kr := range ReadOpaqueKeyrings(bytes.NewBuffer(buf.Bytes())) {
		if opkr != nil {
			t.Fatal("unexpected keyring")
		}
		opkr = kr
	}
	assert.Equal(t, len(opkr.Packets), 24)
}
*/
