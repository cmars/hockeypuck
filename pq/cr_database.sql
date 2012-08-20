--
--   Hockeypuck - OpenPGP key server
--   Copyright (C) 2012  Casey Marshall
--
--   This program is free software: you can redistribute it and/or modify
--   it under the terms of the GNU Affero General Public License as published by
--   the Free Software Foundation, version 3.
--
--   This program is distributed in the hope that it will be useful,
--   but WITHOUT ANY WARRANTY; without even the implied warranty of
--   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--   GNU Affero General Public License for more details.
--
--   You should have received a copy of the GNU Affero General Public License
--   along with this program.  If not, see <http://www.gnu.org/licenses/>.
--

-- Primary key 'uuid' columns contain randomly generated, 256-bit values
-- represented as a base-85 string

--
-- pub_key identifies a primary public key fingerprint.
-- 
CREATE TABLE IF NOT EXISTS pub_key (
	-- Primary key identifier for a public key
	uuid TEXT NOT NULL,
	-- Time when the public key was first added to this key server
	addition TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
	-- Time when the public key was created
	creation TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
	-- Time when the public key expires. May be NULL if no expiration
	expiration TIMESTAMP WITH TIME ZONE,
	-- State of the public key. 0 is always an valid, active state
	state INT,
	-- 20-byte public key fingerprint, as a hexadecimal string
	fingerprint TEXT,
	-- Integer code representing the algorithm used for the public key
	-- as specified in RFC 4880, Section 9.1
	algorithm INT,
	-- Public key length
	key_len INT,
	PRIMARY KEY (uuid),
	UNIQUE (fingerprint, algorithm, key_len)
);

--
-- key_log tracks revisions of a public key ring
-- sent to the keyserver.
--
CREATE TABLE IF NOT EXISTS key_log (
	-- Primary key identifier for a key revision
	uuid TEXT NOT NULL,
	-- Time when the revision was created
	creation TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
	-- State of the public key. 0 is always an valid, active revision
	state INT DEFAULT 0 NOT NULL,
	-- Foreign-key reference to the public key of this revision
	pub_key_uuid TEXT,
	-- Sequence ID number assigned to the revision. Revision IDs
	-- are not consecutive for a given public key, this is just used for sorting
	revision SERIAL NOT NULL,
	-- The full ASCII-armored public key ring at a given revision
	armor TEXT,
	-- SHA-512 message digest of the armored block
	sha512 TEXT,
	PRIMARY KEY (uuid),
	UNIQUE (pub_key_uuid, revision),
	UNIQUE (sha512),
	FOREIGN KEY (pub_key_uuid) REFERENCES pub_key (uuid)
);

--
-- user_id stores all the User ID packets associated with
-- a public key for easy searching.
--
CREATE TABLE IF NOT EXISTS user_id (
	-- Primary key identifier for a user id
	uuid TEXT,
	-- Time when the user ID was first added to the public key on this server
	addition TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
	-- Time when the user ID was created
	creation TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	-- Time when the user ID expires. May be NULL if no expiration
	expiration TIMESTAMP,
	-- State of the public key. 0 is always an valid, active revision
	state INT DEFAULT 0 NOT NULL,
	-- Foreign-key reference to the public key of this revision
	pub_key_uuid TEXT,
	-- Text contents of the user ID. Usually 'Somebody (comment) <somebody@example.com>'
	text TEXT NOT NULL,
	-- Text-searchable content used for a full text search
	ts TSVECTOR NOT NULL,
	PRIMARY KEY (uuid),
	FOREIGN KEY (pub_key_uuid) REFERENCES pub_key (uuid)
);

--
-- Full-text index on User ID text
--
CREATE INDEX user_id_tsindex_idx ON user_id USING gin(ts);

