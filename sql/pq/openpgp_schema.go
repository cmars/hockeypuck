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

package pq

/*

   Notes on Hockeypuck OpenPGP SQL schema
   ======================================

   Common columns
   --------------
   Most tables contain the columns: uuid, creation, expiration and state.

   uuid
   ~~~~
   The UUID is a randomly generated value with an almost certain probability of uniqueness.
   It is the responsibility of the application to detect a UUID collision and roll again.
   A randomly-generated base64 string representative of 256 bits should suffice.

   creation & expiration
   ~~~~~~~~~~~~~~~~~~~~~
   Most tables represent an OpenPGP packet. These timestamps should match the
   actual packet's content meaning as defined in RFC 4880.

   state
   ~~~~~
   The 'state' is a Hockeypuck-reserved value which is intended to disposition
   records outside of the RFC 4880 and HKP server specifications. It may lack
   meaning initially for some records, but is reserved for later use.
   Some plans for state:

    - Flagging a key as garbage, spam, or in general disuse.
    - Limiting the visibility or distribution of the key, subkey or signature.

   For example, a public keyserver exposes UID certifications which can be easily
   harvested to reproduce a social graph. Hockeypuck could hide these certifications
   to unauthenticated queries, and only reveal them to requests that are signed with the
   OpenPGP public keys that are actually a part of the social graph.

   packet
   ~~~~~~
   The original OpenPGP binary packet data is stored verbatim in the database.
   All other columns exist for the purpose of performance and convenience.
   The Hockeypuck server should assert consistency between these on insert/update,
   as well as in an integrity verification utility.

*/

const CreateTable_OpenpgpPubkey = `
CREATE TABLE IF NOT EXISTS openpgp_pubkey (
-----------------------------------------------------------------------
-- Universally-unique identifer
uuid TEXT NOT NULL,
-- Public key creation timestamp
creation TIMESTAMP WITH TIME ZONE NOT NULL,
-- Public key expiration timestamp (if any)
expiration TIMESTAMP WITH TIME ZONE,
-- State flag for this record
state INTEGER NOT NULL DEFAULT 0,
-- Binary contents of the OpenPGP packet
packet bytea NOT NULL,
-----------------------------------------------------------------------
-- Creation time of this public key fingerprint in the database
ctime TIMESTAMP WITH TIME ZONE NOT NULL,
-- Last-modified time of this public key fingerprint in the database
mtime TIMESTAMP WITH TIME ZONE NOT NULL,
-- MD5 digest of the entire public key contents, compatible with SKS
md5 TEXT NOT NULL,
-- SHA256 digest of the entire public key contents, using same method
sha256 TEXT NOT NULL,
-- Reference to a revocation on this primary key
revsig_uuid TEXT,
-----------------------------------------------------------------------
-- Full public key fingerprint, LSB-to-MSB, lowercased hex
rfingerprint TEXT NOT NULL,
-- Public-key algorithm, RFC 4880, Section 9.1
algorithm INTEGER NOT NULL,
-- Public-key bit length
bit_len INTEGER NOT NULL,
-----------------------------------------------------------------------
PRIMARY KEY (uuid),
UNIQUE (md5),
UNIQUE (sha256),
UNIQUE (rfingerprint)
)
`

const CreateTable_OpenpgpSubkey = `
CREATE TABLE IF NOT EXISTS openpgp_subkey (
-----------------------------------------------------------------------
-- Universally-unique identifer
uuid TEXT NOT NULL,
-- Public key creation timestamp
creation TIMESTAMP WITH TIME ZONE NOT NULL,
-- Public key expiration timestamp (if any)
expiration TIMESTAMP WITH TIME ZONE,
-- State flag for this record
state INTEGER NOT NULL DEFAULT 0,
-- Binary contents of the OpenPGP packet
packet bytea NOT NULL,
-----------------------------------------------------------------------
-- Primary public key to which the subkey belongs
pubkey_uuid TEXT NOT NULL,
-- Reference to a revocation signature on this sub key, if any
revsig_uuid TEXT,
-----------------------------------------------------------------------
-- Subkey fingerprint, LSB-to-MSB, lowercased hex
rfingerprint TEXT NOT NULL,
-- Public-key algorithm, RFC 4880, Section 9.1
algorithm INTEGER NOT NULL,
-- Public-key bit length
bit_len INTEGER NOT NULL,
-----------------------------------------------------------------------
PRIMARY KEY (uuid),
UNIQUE (rfingerprint),
FOREIGN KEY (pubkey_uuid) REFERENCES openpgp_pubkey(uuid)
)
`

const CreateTable_OpenpgpUid = `
CREATE TABLE IF NOT EXISTS openpgp_uid (
-----------------------------------------------------------------------
-- Universally-unique identifer
uuid TEXT NOT NULL,
-- User ID creation timestamp
creation TIMESTAMP WITH TIME ZONE NOT NULL,
-- User ID expiration timestamp (if any)
expiration TIMESTAMP WITH TIME ZONE,
-- State flag for this record
state INTEGER NOT NULL DEFAULT 0,
-- Binary contents of the OpenPGP packet
packet bytea NOT NULL,
-----------------------------------------------------------------------
-- Public key to which this identity belongs
pubkey_uuid TEXT NOT NULL,
-- Original text of the user identity string
keywords TEXT NOT NULL,
-- Tokenized, fulltext searchable index
keywords_fulltext tsvector NOT NULL,
-----------------------------------------------------------------------
PRIMARY KEY (uuid),
FOREIGN KEY (pubkey_uuid) REFERENCES openpgp_pubkey(uuid)
)
`

const CreateTable_OpenpgpUat = `
CREATE TABLE IF NOT EXISTS openpgp_uat (
-----------------------------------------------------------------------
-- Universally-unique identifer
uuid TEXT NOT NULL,
-- User attribute creation timestamp
creation TIMESTAMP WITH TIME ZONE NOT NULL,
-- User attribute expiration timestamp (if any)
expiration TIMESTAMP WITH TIME ZONE,
-- State flag for this record
state INTEGER NOT NULL DEFAULT 0,
-- Binary contents of the OpenPGP packet
packet bytea,
-----------------------------------------------------------------------
-- Public key to which this identity belongs
pubkey_uuid TEXT,
-- Byte offset in the packet data of the first image, if any
img_offset INTEGER,
-- Byte length of the first image in the packet data, if any
img_length INTEGER,
-----------------------------------------------------------------------
PRIMARY KEY (uuid),
FOREIGN KEY (pubkey_uuid) REFERENCES openpgp_pubkey(uuid)
)
`
const CreateTable_OpenpgpSig = `
CREATE TABLE IF NOT EXISTS openpgp_sig (
-----------------------------------------------------------------------
-- Universally-unique identifer
uuid TEXT NOT NULL,
-- Signature creation timestamp
creation TIMESTAMP WITH TIME ZONE NOT NULL,
-- Signature expiration timestamp (if any)
expiration TIMESTAMP WITH TIME ZONE,
-- State flag for this record
state INTEGER NOT NULL DEFAULT 0,
-- Binary contents of the OpenPGP packet
packet bytea NOT NULL,
-----------------------------------------------------------------------
-- Signature type, RFC 4880, Section 5.2.1
sig_type INTEGER NOT NULL,
-- Key ID (16-character prefix of the public key rfingerprint)
signer TEXT NOT NULL,
-- Matched reference to the signer in *this* database, if found
signer_uuid TEXT,
-- Reference to a revocation on this signature, if any
revsig_uuid TEXT,
-----------------------------------------------------------------------
PRIMARY KEY (uuid),
FOREIGN KEY (signer_uuid) REFERENCES openpgp_pubkey(uuid),
FOREIGN KEY (revsig_uuid) REFERENCES openpgp_sig(uuid)
)
`

const CreateTable_OpenpgpPubkeySig = `
CREATE TABLE IF NOT EXISTS openpgp_pubkey_sig (
-----------------------------------------------------------------------
-- Universally-unique identifer
uuid TEXT NOT NULL,
-- Public key that is signed
pubkey_uuid TEXT NOT NULL,
-- Signature
sig_uuid TEXT NOT NULL,
-----------------------------------------------------------------------
PRIMARY KEY (uuid),
FOREIGN KEY (pubkey_uuid) REFERENCES openpgp_pubkey(uuid),
FOREIGN KEY (sig_uuid) REFERENCES openpgp_sig(uuid)
)
`

const CreateTable_OpenpgpSubkeySig = `
CREATE TABLE IF NOT EXISTS openpgp_subkey_sig (
-----------------------------------------------------------------------
-- Universally-unique identifer
uuid TEXT NOT NULL,
-- Sub key that is signed
subkey_uuid TEXT NOT NULL,
-- Signature
sig_uuid TEXT NOT NULL,
-----------------------------------------------------------------------
PRIMARY KEY (uuid),
FOREIGN KEY (subkey_uuid) REFERENCES openpgp_subkey(uuid),
FOREIGN KEY (sig_uuid) REFERENCES openpgp_sig(uuid)
)
`

const CreateTable_OpenpgpUidSig = `
CREATE TABLE IF NOT EXISTS openpgp_uid_sig (
-----------------------------------------------------------------------
-- Universally-unique identifer
uuid TEXT NOT NULL,
-- User ID that is signed
uid_uuid TEXT NOT NULL,
-- Signature
sig_uuid TEXT NOT NULL,
-----------------------------------------------------------------------
PRIMARY KEY (uuid),
FOREIGN KEY (uid_uuid) REFERENCES openpgp_uid(uuid),
FOREIGN KEY (sig_uuid) REFERENCES openpgp_sig(uuid)
)
`

const CreateTable_OpenpgpUatSig = `
CREATE TABLE IF NOT EXISTS openpgp_uat_sig (
-----------------------------------------------------------------------
-- Universally-unique identifer
uuid TEXT NOT NULL,
-- UID that is signed
uat_uuid TEXT NOT NULL,
-- Signature
sig_uuid TEXT NOT NULL,
-----------------------------------------------------------------------
PRIMARY KEY (uuid),
FOREIGN KEY (uat_uuid) REFERENCES openpgp_uat(uuid),
FOREIGN KEY (sig_uuid) REFERENCES openpgp_sig(uuid)
)
`

const IndexExists_OpenpgpUidFulltext = `
SELECT COUNT (relname) as n FROM pg_class WHERE relname = 'openpgp_uid_fulltext_idx'
`

const CreateIndex_OpenpgpUidFulltext = `
CREATE INDEX openpgp_uid_fulltext_idx ON openpgp_uid USING gin(keywords_fulltext)
`

var CreateTableStatements []string = []string{
	CreateTable_OpenpgpPubkey,
	CreateTable_OpenpgpSubkey,
	CreateTable_OpenpgpUid,
	CreateTable_OpenpgpUat,
	CreateTable_OpenpgpSig,
	CreateTable_OpenpgpPubkeySig,
	CreateTable_OpenpgpSubkeySig,
	CreateTable_OpenpgpUidSig,
	CreateTable_OpenpgpUatSig}
