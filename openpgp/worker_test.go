package openpgp

import (
	"crypto/sha256"
	"github.com/jmoiron/sqlx"
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

func TestRoundTripKey(t *testing.T) {
	w := MustCreateWorker(t)
	key1 := MustInputAscKey(t, "sksdigest.asc")
	kv := ValidateKey(key1)
	assert.Nil(t, kv.KeyError)
	err := w.InsertKey(key1)
	assert.Nil(t, err)
	key2, err := w.fetchKey(key1.RFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, key1.userIds[0].Keywords, "Jenny Ondioline <jennyo@transient.net>")
	assert.Equal(t, key1.userIds[0].Keywords, key2.userIds[0].Keywords)
	h1 := SksDigest(key1, sha256.New())
	h2 := SksDigest(key2, sha256.New())
	assert.Equal(t, h1, h2)
}
