/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012, 2013  Casey Marshall

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

import (
	_ "code.google.com/p/go.crypto/md4"
	_ "code.google.com/p/go.crypto/ripemd160"
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
)

type resolver struct {
	Pubkey *Pubkey
}

// Resolve resolves and connects relationship references
// between the different packet records in the key material.
func Resolve(pubkey *Pubkey) {
	r := &resolver{pubkey}
	pubkey.Visit(r.resolve)
}

func (r *resolver) resolve(rec PacketRecord) (err error) {
	switch p := rec.(type) {
	case *Pubkey:
		r.setSigScope(p.RFingerprint, p.signatures...)
		p.linkSelfSigs()
	case *UserId:
		p.ScopedDigest = p.calcScopedDigest(r.Pubkey)
		r.setSigScope(p.ScopedDigest, p.signatures...)
		p.linkSelfSigs(r.Pubkey)
		// linkSelfSigs needs to set creation & expiration
	case *UserAttribute:
		p.ScopedDigest = p.calcScopedDigest(r.Pubkey)
		r.setSigScope(p.ScopedDigest, p.signatures...)
		p.linkSelfSigs(r.Pubkey)
		// linkSelfSigs needs to set creation & expiration
	case *Subkey:
		r.setSigScope(p.RFingerprint, p.signatures...)
		p.linkSelfSigs(r.Pubkey)
	case *Unsupported:
		if p.prevRecord != nil {
			p.PrevDigest = p.prevRecord.Uuid()
		}
		p.ScopedDigest = p.calcScopedDigest(r.Pubkey)
	}
	return
}

func (r *resolver) setSigScope(scope string, sigs ...*Signature) {
	for _, sig := range sigs {
		sig.ScopedDigest = sig.calcScopedDigest(r.Pubkey, scope)
	}
}
