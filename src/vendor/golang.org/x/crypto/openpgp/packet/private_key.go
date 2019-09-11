// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"io"
	"io/ioutil"
	"math/big"
	"strconv"
	"time"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/openpgp/ecdh"
	"golang.org/x/crypto/openpgp/elgamal"
	"golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/internal/encoding"
	"golang.org/x/crypto/openpgp/s2k"
	"golang.org/x/crypto/rsa"
)

// PrivateKey represents a possibly encrypted private key. See RFC 4880,
// section 5.5.3.
type PrivateKey struct {
	PublicKey
	Encrypted     bool // if true then the private key is unavailable until Decrypt has been called.
	encryptedData []byte
	cipher        CipherFunction
	s2k           func(out, in []byte)
	PrivateKey    interface{} // An *{rsa|dsa|ecdsa}.PrivateKey or a crypto.Signer.
	sha1Checksum  bool
	iv            []byte

	// s2k related
	salt      []byte
	s2kConfig s2k.Config
	s2kType   S2KType
}

//S2KType s2k packet type
type S2KType uint8

const (
	// S2KNON unencrypt
	S2KNON S2KType = 0
	// S2KSHA1 sha1 sum check
	S2KSHA1 S2KType = 254
	// S2KCHECKSUM sum check
	S2KCHECKSUM S2KType = 255
)

func NewRSAPrivateKey(currentTime time.Time, priv *rsa.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewRSAPublicKey(currentTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func NewDSAPrivateKey(currentTime time.Time, priv *dsa.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewDSAPublicKey(currentTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func NewElGamalPrivateKey(currentTime time.Time, priv *elgamal.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewElGamalPublicKey(currentTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func NewECDSAPrivateKey(currentTime time.Time, priv *ecdsa.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewECDSAPublicKey(currentTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

// NewSignerPrivateKey creates a sign-only PrivateKey from a crypto.Signer that
// implements RSA or ECDSA.
func NewSignerPrivateKey(currentTime time.Time, signer crypto.Signer) *PrivateKey {
	pk := new(PrivateKey)
	switch pubkey := signer.Public().(type) {
	case rsa.PublicKey:
		pk.PublicKey = *NewRSAPublicKey(currentTime, &pubkey)
		pk.PubKeyAlgo = PubKeyAlgoRSASignOnly
	case ecdsa.PublicKey:
		pk.PublicKey = *NewECDSAPublicKey(currentTime, &pubkey)
	case ed25519.PublicKey:
		pk.PublicKey = *NewEdDSAPublicKey(currentTime, pubkey)
	default:
		panic("openpgp: unknown crypto.Signer type in NewSignerPrivateKey")
	}
	pk.PrivateKey = signer
	return pk
}

func NewECDHPrivateKey(currentTime time.Time, priv *ecdh.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewECDHPublicKey(currentTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func NewEdDSAPrivateKey(currentTime time.Time, priv ed25519.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewEdDSAPublicKey(currentTime, priv.Public().(ed25519.PublicKey))
	pk.PrivateKey = priv
	return pk
}

func (pk *PrivateKey) parse(r io.Reader) (err error) {
	err = (&pk.PublicKey).parse(r)
	if err != nil {
		return
	}
	var buf [1]byte
	_, err = readFull(r, buf[:])
	if err != nil {
		return
	}

	s2kType := buf[0]

	switch s2kType {
	case 0:
		pk.s2k = nil
		pk.Encrypted = false
	case 254, 255:
		_, err = readFull(r, buf[:])
		if err != nil {
			return
		}
		pk.cipher = CipherFunction(buf[0])
		pk.Encrypted = true
		pk.s2k, err = s2k.Parse(r)
		if err != nil {
			return
		}
		if s2kType == 254 {
			pk.sha1Checksum = true
		}
	default:
		return errors.UnsupportedError("deprecated s2k function in private key")
	}

	if pk.Encrypted {
		blockSize := pk.cipher.blockSize()
		if blockSize == 0 {
			return errors.UnsupportedError("unsupported cipher in private key: " + strconv.Itoa(int(pk.cipher)))
		}
		pk.iv = make([]byte, blockSize)
		_, err = readFull(r, pk.iv)
		if err != nil {
			return
		}
	}

	pk.encryptedData, err = ioutil.ReadAll(r)
	if err != nil {
		return
	}

	if !pk.Encrypted {
		return pk.parsePrivateKey(pk.encryptedData)
	}

	return
}

func mod64kHash(d []byte) uint16 {
	var h uint16
	for _, b := range d {
		h += uint16(b)
	}
	return h
}

func (pk *PrivateKey) Serialize(w io.Writer) (err error) {
	buf := bytes.NewBuffer(nil)
	err = pk.PublicKey.serializeWithoutHeaders(buf)
	if err != nil {
		return
	}

	privateKeyBuf := bytes.NewBuffer(nil)
	if pk.Encrypted {
		pk.SerializeEncrypted(privateKeyBuf)
	} else {
		pk.SerializeUnEncrypted(privateKeyBuf)
	}

	ptype := packetTypePrivateKey
	contents := buf.Bytes()
	privateKeyBytes := privateKeyBuf.Bytes()
	if pk.IsSubkey {
		ptype = packetTypePrivateSubkey
	}
	err = serializeHeader(w, ptype, len(contents)+len(privateKeyBytes))
	if err != nil {
		return
	}
	_, err = w.Write(contents)
	if err != nil {
		return
	}
	_, err = w.Write(privateKeyBytes)
	if err != nil {
		return
	}
	return
}

// SerializeUnEncrypted ..
func (pk *PrivateKey) SerializeUnEncrypted(w io.Writer) (err error) {
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{uint8(S2KNON)} /* no encryption */)
	switch priv := pk.PrivateKey.(type) {
	case *rsa.PrivateKey:
		err = serializeRSAPrivateKey(buf, priv)
	case *dsa.PrivateKey:
		err = serializeDSAPrivateKey(buf, priv)
	case *elgamal.PrivateKey:
		err = serializeElGamalPrivateKey(buf, priv)
	case *ecdsa.PrivateKey:
		err = serializeECDSAPrivateKey(buf, priv)
	default:
		err = errors.InvalidArgumentError("unknown private key type")
	}
	privateKeyBytes := buf.Bytes()
	if pk.sha1Checksum {
		h := sha1.New()
		h.Write(privateKeyBytes)
		sum := h.Sum(nil)
		privateKeyBytes = append(privateKeyBytes, sum...)
	} else {
		checksum := mod64kHash(privateKeyBytes)
		var checksumBytes [2]byte
		checksumBytes[0] = byte(checksum >> 8)
		checksumBytes[1] = byte(checksum)
		privateKeyBytes = append(privateKeyBytes, checksumBytes[:]...)
	}
	w.Write(privateKeyBytes)
	return
}

//SerializeEncrypted serialize encrypted privatekey
func (pk *PrivateKey) SerializeEncrypted(w io.Writer) error {
	privateKeyBuf := bytes.NewBuffer(nil)
	encodedKeyBuf := bytes.NewBuffer(nil)
	encodedKeyBuf.Write([]byte{uint8(pk.s2kType)})
	encodedKeyBuf.Write([]byte{uint8(pk.cipher)})
	encodedKeyBuf.Write([]byte{pk.s2kConfig.S2KMode})
	hashID, ok := s2k.HashToHashId(pk.s2kConfig.Hash)
	if !ok {
		return errors.UnsupportedError("no such hash")
	}
	encodedKeyBuf.Write([]byte{hashID})
	encodedKeyBuf.Write(pk.salt)
	encodedKeyBuf.Write([]byte{pk.s2kConfig.EncodedCount()})

	privateKeyBuf.Write(pk.encryptedData)

	encodedKey := encodedKeyBuf.Bytes()
	privateKeyBytes := privateKeyBuf.Bytes()

	w.Write(encodedKey)
	w.Write(pk.iv)
	w.Write(privateKeyBytes)

	return nil
}

func serializeRSAPrivateKey(w io.Writer, priv *rsa.PrivateKey) error {
	if _, err := w.Write(new(encoding.MPI).SetBig(priv.D).EncodedBytes()); err != nil {
		return err
	}
	if _, err := w.Write(new(encoding.MPI).SetBig(priv.Primes[1]).EncodedBytes()); err != nil {
		return err
	}
	if _, err := w.Write(new(encoding.MPI).SetBig(priv.Primes[0]).EncodedBytes()); err != nil {
		return err
	}
	_, err := w.Write(new(encoding.MPI).SetBig(priv.Precomputed.Qinv).EncodedBytes())
	return err
}

func serializeDSAPrivateKey(w io.Writer, priv *dsa.PrivateKey) error {
	_, err := w.Write(new(encoding.MPI).SetBig(priv.X).EncodedBytes())
	return err
}

func serializeElGamalPrivateKey(w io.Writer, priv *elgamal.PrivateKey) error {
	_, err := w.Write(new(encoding.MPI).SetBig(priv.X).EncodedBytes())
	return err
}

func serializeECDSAPrivateKey(w io.Writer, priv *ecdsa.PrivateKey) error {
	_, err := w.Write(new(encoding.MPI).SetBig(priv.D).EncodedBytes())
	return err
}

func serializeEdDSAPrivateKey(w io.Writer, priv ed25519.PrivateKey) error {
	keySize := ed25519.PrivateKeySize - ed25519.PublicKeySize
	_, err := w.Write(encoding.NewMPI(priv[:keySize]).EncodedBytes())
	return err
}

func serializeECDHPrivateKey(w io.Writer, priv *ecdh.PrivateKey) error {
	_, err := w.Write(encoding.NewMPI(priv.D).EncodedBytes())
	return err
}



// Decrypt decrypts an encrypted private key using a passphrase.
func (pk *PrivateKey) Decrypt(passphrase []byte) error {
	if !pk.Encrypted {
		return nil
	}

	key := make([]byte, pk.cipher.KeySize())
	pk.s2k(key, passphrase)
	block := pk.cipher.new(key)
	cfb := cipher.NewCFBDecrypter(block, pk.iv)

	data := make([]byte, len(pk.encryptedData))
	cfb.XORKeyStream(data, pk.encryptedData)

	if pk.sha1Checksum {
		if len(data) < sha1.Size {
			return errors.StructuralError("truncated private key data")
		}
		h := sha1.New()
		h.Write(data[:len(data)-sha1.Size])
		sum := h.Sum(nil)
		if !bytes.Equal(sum, data[len(data)-sha1.Size:]) {
			return errors.StructuralError("private key checksum failure")
		}
		data = data[:len(data)-sha1.Size]
	} else {
		if len(data) < 2 {
			return errors.StructuralError("truncated private key data")
		}
		var sum uint16
		for i := 0; i < len(data)-2; i++ {
			sum += uint16(data[i])
		}
		if data[len(data)-2] != uint8(sum>>8) ||
			data[len(data)-1] != uint8(sum) {
			return errors.StructuralError("private key checksum failure")
		}
		data = data[:len(data)-2]
	}

	return pk.parsePrivateKey(data)
}

// Encrypt encrypts an unencrypted private key using a passphrase.
func (pk *PrivateKey) Encrypt(passphrase []byte) error {
	privateKeyBuf := bytes.NewBuffer(nil)
	err := pk.serializePrivateKey(privateKeyBuf)
	if err != nil {
		return err
	}

	//Default config of private key encryption
	pk.cipher = CipherAES256
	pk.s2kConfig = s2k.Config{
		S2KMode:  3, //Iterated
		S2KCount: 65536,
		Hash:     crypto.SHA256,
	}

	privateKeyBytes := privateKeyBuf.Bytes()
	key := make([]byte, pk.cipher.KeySize())
	pk.salt = make([]byte, 8)
	rand.Read(pk.salt)
	pk.sha1Checksum = true
	pk.s2k = func(out, in []byte) {
		s2k.Iterated(out, pk.s2kConfig.Hash.New(), in, pk.salt, pk.s2kConfig.S2KCount)
	}
	pk.s2k(key, passphrase)
	block := pk.cipher.new(key)
	pk.iv = make([]byte, pk.cipher.blockSize())
	rand.Read(pk.iv)
	cfb := cipher.NewCFBEncrypter(block, pk.iv)

	if pk.sha1Checksum {
		pk.s2kType = S2KSHA1
		h := sha1.New()
		h.Write(privateKeyBytes)
		sum := h.Sum(nil)
		privateKeyBytes = append(privateKeyBytes, sum...)
	} else {
		pk.s2kType = S2KCHECKSUM
		var sum uint16
		for i := 0; i < len(privateKeyBytes); i++ {
			sum += uint16(privateKeyBytes[i])
		}
		privateKeyBytes = append(privateKeyBytes, uint8(sum>>8))
		privateKeyBytes = append(privateKeyBytes, uint8(sum))
	}

	pk.encryptedData = make([]byte, len(privateKeyBytes))

	cfb.XORKeyStream(pk.encryptedData, privateKeyBytes)

	pk.Encrypted = true

	pk.PrivateKey = nil
	return err
}

func (pk *PrivateKey) serializePrivateKey(w io.Writer) (err error) {

	switch priv := pk.PrivateKey.(type) {
	case *rsa.PrivateKey:
		err = serializeRSAPrivateKey(w, priv)
	case *dsa.PrivateKey:
		err = serializeDSAPrivateKey(w, priv)
	case *elgamal.PrivateKey:
		err = serializeElGamalPrivateKey(w, priv)
	case *ecdsa.PrivateKey:
		err = serializeECDSAPrivateKey(w, priv)
	case ed25519.PrivateKey:
		err = serializeEdDSAPrivateKey(w, priv)
	case *ecdh.PrivateKey:
		err = serializeECDHPrivateKey(w, priv)
	default:
		err = errors.InvalidArgumentError("unknown private key type")
	}
	return
}

func (pk *PrivateKey) parsePrivateKey(data []byte) (err error) {
	switch pk.PublicKey.PubKeyAlgo {
	case PubKeyAlgoRSA, PubKeyAlgoRSASignOnly, PubKeyAlgoRSAEncryptOnly:
		return pk.parseRSAPrivateKey(data)
	case PubKeyAlgoDSA:
		return pk.parseDSAPrivateKey(data)
	case PubKeyAlgoElGamal:
		return pk.parseElGamalPrivateKey(data)
	case PubKeyAlgoECDSA:
		return pk.parseECDSAPrivateKey(data)
	case PubKeyAlgoECDH:
		return pk.parseECDHPrivateKey(data)
	case PubKeyAlgoEdDSA:
		return pk.parseEdDSAPrivateKey(data)
	}
	panic("impossible")
}

func (pk *PrivateKey) parseRSAPrivateKey(data []byte) (err error) {
	rsaPub := pk.PublicKey.PublicKey.(*rsa.PublicKey)
	rsaPriv := new(rsa.PrivateKey)
	rsaPriv.PublicKey = *rsaPub

	buf := bytes.NewBuffer(data)
	d := new(encoding.MPI)
	if _, err := d.ReadFrom(buf); err != nil {
		return err
	}

	p := new(encoding.MPI)
	if _, err := p.ReadFrom(buf); err != nil {
		return err
	}

	q := new(encoding.MPI)
	if _, err := q.ReadFrom(buf); err != nil {
		return err
	}

	rsaPriv.D = new(big.Int).SetBytes(d.Bytes())
	rsaPriv.Primes = make([]*big.Int, 2)
	rsaPriv.Primes[0] = new(big.Int).SetBytes(p.Bytes())
	rsaPriv.Primes[1] = new(big.Int).SetBytes(q.Bytes())
	if err := rsaPriv.Validate(); err != nil {
		return err
	}
	rsaPriv.Precompute()
	pk.PrivateKey = rsaPriv
	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}

func (pk *PrivateKey) parseDSAPrivateKey(data []byte) (err error) {
	dsaPub := pk.PublicKey.PublicKey.(*dsa.PublicKey)
	dsaPriv := new(dsa.PrivateKey)
	dsaPriv.PublicKey = *dsaPub

	buf := bytes.NewBuffer(data)
	x := new(encoding.MPI)
	if _, err := x.ReadFrom(buf); err != nil {
		return err
	}

	dsaPriv.X = new(big.Int).SetBytes(x.Bytes())
	pk.PrivateKey = dsaPriv
	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}

func (pk *PrivateKey) parseElGamalPrivateKey(data []byte) (err error) {
	pub := pk.PublicKey.PublicKey.(*elgamal.PublicKey)
	priv := new(elgamal.PrivateKey)
	priv.PublicKey = *pub

	buf := bytes.NewBuffer(data)
	x := new(encoding.MPI)
	if _, err := x.ReadFrom(buf); err != nil {
		return err
	}

	priv.X = new(big.Int).SetBytes(x.Bytes())
	pk.PrivateKey = priv
	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}

func (pk *PrivateKey) parseECDSAPrivateKey(data []byte) (err error) {
	ecdsaPub := pk.PublicKey.PublicKey.(*ecdsa.PublicKey)
	ecdsaPriv := new(ecdsa.PrivateKey)
	ecdsaPriv.PublicKey = *ecdsaPub

	buf := bytes.NewBuffer(data)
	d := new(encoding.MPI)
	if _, err := d.ReadFrom(buf); err != nil {
		return err
	}

	ecdsaPriv.D = new(big.Int).SetBytes(d.Bytes())
	pk.PrivateKey = ecdsaPriv
	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}

func (pk *PrivateKey) parseECDHPrivateKey(data []byte) (err error) {
	ecdhPub := pk.PublicKey.PublicKey.(*ecdh.PublicKey)
	ecdhPriv := new(ecdh.PrivateKey)
	ecdhPriv.PublicKey = *ecdhPub

	buf := bytes.NewBuffer(data)
	d := new(encoding.MPI)
	if _, err := d.ReadFrom(buf); err != nil {
		return err
	}

	ecdhPriv.D = d.Bytes()
	pk.PrivateKey = ecdhPriv
	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}

func (pk *PrivateKey) parseEdDSAPrivateKey(data []byte) (err error) {
	eddsaPub := pk.PublicKey.PublicKey.(ed25519.PublicKey)
	eddsaPriv := make(ed25519.PrivateKey, ed25519.PrivateKeySize)

	buf := bytes.NewBuffer(data)
	d := new(encoding.MPI)
	if _, err := d.ReadFrom(buf); err != nil {
		return err
	}

	copy(eddsaPriv[:32], d.Bytes())
	copy(eddsaPriv[32:], eddsaPub[:])

	pk.PrivateKey = eddsaPriv
	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}
