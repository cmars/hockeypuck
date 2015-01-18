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

// hockeypuck is an OpenPGP keyserver.
package main

import (
	"encoding/hex"
	"strings"

	"gopkg.in/errgo.v1"
	"gopkg.in/hockeypuck/conflux.v2"
	"gopkg.in/hockeypuck/conflux.v2/recon"
	log "gopkg.in/hockeypuck/logrus.v0"
	"launchpad.net/gnuflag"

	"github.com/hockeypuck/hockeypuck/openpgp"
	"github.com/hockeypuck/hockeypuck/util"
)

type deleteCmd struct {
	configuredCmd
	keyHash     string
	fingerprint string

	keyHashBuf []byte
	db         *openpgp.DB
	ptree      recon.PrefixTree
}

func (ec *deleteCmd) Name() string { return "delete" }

func (ec *deleteCmd) Desc() string { return "Delete key hash from prefix tree" }

func newDeleteCmd() *deleteCmd {
	cmd := new(deleteCmd)
	flags := gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	flags.StringVar(&cmd.configPath, "config", "", "Hockeypuck configuration file")
	flags.StringVar(&cmd.keyHash, "keyHash", "", "Delete key hash")
	flags.StringVar(&cmd.fingerprint, "fingerprint", "", "Delete key fingerprint")
	cmd.flags = flags
	return cmd
}

func (ec *deleteCmd) Main() error {
	err := ec.configuredCmd.Main()
	if err != nil {
		return errgo.Mask(err)
	}

	if ec.keyHash != "" && ec.fingerprint != "" {
		return newUsageError(ec, "cannot specify both --keyHash and --fingerprint")
	}
	ec.db, err = openpgp.NewDB(ec.settings)
	if err != nil {
		return errgo.Mask(err)
	}
	// Ensure tables all exist
	err = ec.db.CreateTables()
	if err != nil {
		return errgo.Mask(err)
	}
	ec.ptree, err = openpgp.NewSksPTree(ec.settings)
	if err != nil {
		return errgo.Mask(err)
	}
	// Create the prefix tree (if not exists)
	err = ec.ptree.Create()
	if err != nil {
		return errgo.Mask(err)
	}
	// Ensure tables all exist
	err = ec.db.CreateTables()
	if err != nil {
		return errgo.Mask(err)
	}
	defer ec.db.Close()
	defer ec.ptree.Close()
	if ec.keyHash != "" {
		err = ec.deleteKeyHash()
		if err != nil {
			return errgo.Mask(err)
		}
	} else if ec.fingerprint != "" {
		err = ec.deleteFingerprint()
		if err != nil {
			return errgo.Mask(err)
		}
	}
	return newUsageError(ec, "one of --keyHash, --fingerprint required")
}

var UpdateFkSql []string = []string{
	`UPDATE openpgp_pubkey SET primary_uid = NULL, primary_uat = NULL, revsig_uuid = NULL
WHERE uuid = $1`,
	`UPDATE openpgp_sig SET revsig_uuid = NULL WHERE pubkey_uuid = $1`,
	`UPDATE openpgp_subkey SET revsig_uuid = NULL WHERE pubkey_uuid = $1`,
	`UPDATE openpgp_uid SET revsig_uuid = NULL WHERE pubkey_uuid = $1`,
	`UPDATE openpgp_uat SET revsig_uuid = NULL WHERE pubkey_uuid = $1`,
	`UPDATE openpgp_subkey SET revsig_uuid = NULL WHERE pubkey_uuid = $1`,
}

var DeleteSigSql string = "DELETE FROM openpgp_sig WHERE uuid = $1"

var DeletePubkeySql []string = []string{
	"DELETE FROM openpgp_uat WHERE pubkey_uuid = $1",
	"DELETE FROM openpgp_uid WHERE pubkey_uuid = $1",
	"DELETE FROM openpgp_subkey WHERE pubkey_uuid = $1",
	"DELETE FROM openpgp_pubkey WHERE uuid = $1",
	"DELETE FROM openpgp_sig WHERE pubkey_uuid = $1",
}

func (ec *deleteCmd) deleteKeyHash() error {
	ec.keyHash = strings.ToLower(ec.keyHash)
	keyHashBuf, err := hex.DecodeString(ec.keyHash)
	if err != nil {
		return errgo.Mask(err)
	}
	if err = ec.ptree.Remove(conflux.Zb(conflux.P_SKS, keyHashBuf)); err != nil {
		log.Errorf("failed to remove key %q from prefix tree: %v", ec.keyHash, err)
	}
	var uuid string
	row, err := ec.db.Query(
		"SELECT uuid FROM openpgp_pubkey WHERE md5 = $1", ec.keyHash)
	if err != nil {
		return errgo.Mask(err)
	}
	if !row.Next() {
		return errgo.Newf("key hash %q not found", ec.keyHash)
	}
	err = row.Scan(&uuid)
	if err != nil {
		return errgo.Mask(err)
	}
	ec.deletePubkey(uuid)
	log.Infof("key %q deleted from prefix tree and database", ec.keyHash)
	return nil
}

func (ec *deleteCmd) deleteFingerprint() error {
	uuid := strings.ToLower(util.Reverse(ec.fingerprint))
	row, err := ec.db.Query(
		"SELECT md5 FROM openpgp_pubkey WHERE uuid = $1", uuid)
	if err != nil {
		return errgo.Mask(err)
	}
	if !row.Next() {
		return errgo.Newf("key %q not found", uuid)
	}
	var keyHash string
	err = row.Scan(&keyHash)
	if err != nil {
		return errgo.Mask(err)
	}
	keyHashBuf, err := hex.DecodeString(keyHash)
	if err != nil {
		return errgo.Mask(err)
	}
	if err = ec.ptree.Remove(conflux.Zb(conflux.P_SKS, keyHashBuf)); err != nil {
		log.Errorf("remove %q from prefix tree: %v", keyHash, err)
	}
	ec.deletePubkey(uuid)
	log.Infof("key %q deleted from prefix tree and database", ec.keyHash)
	return nil
}

func (ec *deleteCmd) deletePubkey(uuid string) {
	for _, sql := range UpdateFkSql {
		openpgp.Execf(ec.db, sql, uuid)
	}
	for _, sql := range DeletePubkeySql {
		openpgp.Execf(ec.db, sql, uuid)
	}
}
