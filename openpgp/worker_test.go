package openpgp

import (
	"code.google.com/p/go.crypto/openpgp/armor"
	"crypto/sha256"
	"github.com/cmars/sqlx"
	"github.com/stretchr/testify/assert"
	"launchpad.net/hockeypuck"
	"testing"
)

func MustCreateWorker(t *testing.T) *Worker {
	db, err := sqlx.Connect("postgres",
		"dbname=postgres host=/var/run/postgresql sslmode=disable")
	assert.Nil(t, err)
	db.Execf("DROP DATABASE IF EXISTS testhkp")
	db.Execf("CREATE DATABASE testhkp")
	hockeypuck.SetConfig(`
[hockeypuck.openpgp.db]
driver="postgres"
dsn="dbname=testhkp host=/var/run/postgresql sslmode=disable"
`)
	w := &Worker{}
	w.initDb()
	return w
}

func MustDestroyWorker(t *testing.T, w *Worker) {
	w.db.Close()
	db, err := sqlx.Connect("postgres",
		"dbname=postgres host=/var/run/postgresql sslmode=disable")
	assert.Nil(t, err)
	db.Execf("DROP DATABASE IF EXISTS testhkp")
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
	for keyRead := range ReadValidKeys(block.Body) {
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
		"uat.asc", "tails.asc"} {
		t.Log(testfile)
		testRoundTripKey(t, testfile)
	}
}

func testRoundTripKey(t *testing.T, testfile string) {
	w := MustCreateWorker(t)
	defer MustDestroyWorker(t, w)
	key1 := MustInputAscKey(t, testfile)
	kv := ValidateKey(key1)
	assert.Nil(t, kv.KeyError)
	err := w.InsertKey(key1)
	assert.Nil(t, err)
	key2, err := w.fetchKey(key1.RFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	//assert.Equal(t, key1.userIds[0].Keywords, "Jenny Ondioline <jennyo@transient.net>")
	//assert.Equal(t, key1.userIds[0].Keywords, key2.userIds[0].Keywords)
	h1 := SksDigest(key1, sha256.New())
	h2 := SksDigest(key2, sha256.New())
	assert.Equal(t, h1, h2)
}
