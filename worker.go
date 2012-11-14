package hockeypuck

import (
	"bytes"
	"log"
	"os"
	"strings"
)

const FIND_KEYS_LIMIT = 10
const INDEX_LIMIT = 50

type Worker interface {
	// Look up keys by search string. Prefix with 0x will look up key id,
	// other strings match on tokenized user ID.
	LookupKeys(search string, limit int) ([]*PubKey, error)
	// Look up a key by ID.
	LookupKey(keyid string) (*PubKey, error)
	// Add ASCII-armored public key
	AddKey(armoredKey string) ([]string, error)
}

type WorkerBase struct {
	L *log.Logger
}

func (w *WorkerBase) Init() {
	if w.L == nil {
		w.L = log.New(os.Stderr, "[hockeypuck]", log.LstdFlags | log.Lshortfile)
	}
}

func GetKey(w Worker, keyid string) (string, error) {
	//w.L.Print("GetKey(", keyid, ")")
	key, err := w.LookupKey(keyid)
	if err != nil {
		return "", InvalidKeyId
	}
	out := bytes.NewBuffer([]byte{})
	err = WriteKey(out, key)
	//w.L.Println(err)
	return string(out.Bytes()), err
}

func FindKeys(w Worker, search string) (string, error) {
	//w.L.Print("FindKeys(", search, ")")
	keys, err := w.LookupKeys(search, FIND_KEYS_LIMIT)
	if err != nil {
		return "", err
	}
	if len(keys) == 0 {
		return "", KeyNotFound
	}
	//w.L.Print(len(keys), "matches")
	buf := bytes.NewBuffer([]byte{})
	for _, key := range keys {
		err = WriteKey(buf, key)
		if err != nil {
			return "", err
		}
	}
	return string(buf.Bytes()), err
}

func Start(hkp *HkpServer, w Worker) (chan interface{}) {
	stop := make(chan interface{})
	go func() {
		for {
			select {
			case lookup := <-hkp.LookupRequests:
				switch lookup.Op {
				case Get:
					var armor string
					var err error
					if lookup.Exact || strings.HasPrefix(lookup.Search, "0x") {
						armor, err = GetKey(w, lookup.Search[2:])
					} else {
						armor, err = FindKeys(w, lookup.Search)
					}
					lookup.Response() <- &MessageResponse{ Content: armor, Err: err }
				case Index, Vindex:
					var key *PubKey
					var err error
					keys := []*PubKey{}
					if lookup.Exact || strings.HasPrefix(lookup.Search, "0x") {
						key, err = w.LookupKey(lookup.Search[2:])
						keys = append(keys, key)
					} else {
						keys, err = w.LookupKeys(lookup.Search, INDEX_LIMIT)
					}
					lookup.Response() <- &IndexResponse{ Keys: keys, Err: err, Lookup: lookup }
				default:
					lookup.Response() <- &NotImplementedResponse{}
				}
			case add := <-hkp.AddRequests:
				fps, err := w.AddKey(add.Keytext)
				add.Response() <- &AddResponse{ Fingerprints: fps, Err: err }
			case _, isOpen := <-stop:
				if !isOpen {
					return
				}
			}
		}
	}()
	return stop
}
