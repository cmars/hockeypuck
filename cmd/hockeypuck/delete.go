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
	"fmt"
	"log"
	"strings"

	"github.com/cmars/conflux"
	"github.com/cmars/conflux/recon"

	"launchpad.net/gnuflag"
	. "github.com/hockeypuck/hockeypuck"
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

func (ec *deleteCmd) Main() {
	var err error
	if ec.keyHash != "" && ec.fingerprint != "" {
		Usage(ec, "Cannot specify both --keyHash and --fingerprint. Choose one.")
	}
	ec.configuredCmd.Main()
	InitLog()
	if ec.db, err = openpgp.NewDB(); err != nil {
		die(err)
	}
	// Ensure tables all exist
	if err = ec.db.CreateTables(); err != nil {
		die(err)
	}
	reconSettings := recon.NewSettings(openpgp.Config().Settings.TomlTree)
	if ec.ptree, err = openpgp.NewSksPTree(reconSettings); err != nil {
		die(err)
	}
	// Create the prefix tree (if not exists)
	if err = ec.ptree.Create(); err != nil {
		die(err)
	}
	// Ensure tables all exist
	if err = ec.db.CreateTables(); err != nil {
		die(err)
	}
	defer ec.db.Close()
	defer ec.ptree.Close()
	if ec.keyHash != "" {
		ec.deleteKeyHash()
	} else if ec.fingerprint != "" {
		ec.deleteFingerprint()
	} else {
		Usage(ec, "One of --keyHash or --fingerprint is required")
	}
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

func (ec *deleteCmd) deleteKeyHash() {
	ec.keyHash = strings.ToLower(ec.keyHash)
	keyHashBuf, err := hex.DecodeString(ec.keyHash)
	if err != nil {
		die(err)
	}
	if err = ec.ptree.Remove(conflux.Zb(conflux.P_SKS, keyHashBuf)); err != nil {
		log.Println("Remove [%s] from prefix tree: %v", ec.keyHash, err)
	}
	var uuid string
	row, err := ec.db.Query(
		"SELECT uuid FROM openpgp_pubkey WHERE md5 = $1", ec.keyHash)
	if err != nil {
		die(err)
	}
	if !row.Next() {
		die(fmt.Errorf("Key hash [%d] not found", ec.keyHash))
	}
	err = row.Scan(&uuid)
	if err != nil {
		die(err)
	}
	ec.deletePubkey(uuid)
	log.Println(ec.keyHash, "deleted from prefix tree and database")
}

func (ec *deleteCmd) deleteFingerprint() {
	uuid := strings.ToLower(util.Reverse(ec.fingerprint))
	row, err := ec.db.Query(
		"SELECT md5 FROM openpgp_pubkey WHERE uuid = $1", uuid)
	if err != nil {
		die(err)
	}
	if !row.Next() {
		die(fmt.Errorf("Key fingerprint [%s] not found", uuid))
	}
	var keyHash string
	err = row.Scan(&keyHash)
	if err != nil {
		die(err)
	}
	keyHashBuf, err := hex.DecodeString(keyHash)
	if err != nil {
		die(err)
	}
	if err = ec.ptree.Remove(conflux.Zb(conflux.P_SKS, keyHashBuf)); err != nil {
		log.Println("Remove [%s] from prefix tree: %v", keyHash, err)
	}
	ec.deletePubkey(uuid)
	log.Println(ec.keyHash, "deleted from prefix tree and database")
}

func (ec *deleteCmd) deletePubkey(uuid string) {
	for _, sql := range UpdateFkSql {
		ec.db.Execf(sql, uuid)
	}
	for _, sql := range DeletePubkeySql {
		ec.db.Execf(sql, uuid)
	}
}
