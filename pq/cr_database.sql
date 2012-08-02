
--
-- pub_key identifies a primary public key fingerprint.
-- 
CREATE TABLE IF NOT EXISTS pub_key (
	uuid TEXT NOT NULL,
	creation TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
	expiration TIMESTAMP,
	state INT,
	fingerprint TEXT,
	algorithm INT,
	key_len INT,
	PRIMARY KEY (uuid),
	UNIQUE (fingerprint, algorithm, key_len)
);

--
-- key_log tracks revisions of a public key ring
-- sent to the keyserver.
--
CREATE TABLE IF NOT EXISTS key_log (
	uuid TEXT NOT NULL,
	creation TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
	state INT DEFAULT 0 NOT NULL,
	pub_key_uuid TEXT,
	revision SERIAL NOT NULL,
	armor TEXT,
	PRIMARY KEY (uuid),
	UNIQUE (pub_key_uuid, revision),
	FOREIGN KEY (pub_key_uuid) REFERENCES pub_key (uuid)
);

--
-- user_id stores all the User ID packets associated with
-- a public key for easy searching.
--
CREATE TABLE IF NOT EXISTS user_id (
	uuid TEXT,
	creation TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	expiration TIMESTAMP,
	state INT DEFAULT 0 NOT NULL,
	pub_key_uuid TEXT,
	text TEXT NOT NULL,
	ts TSVECTOR NOT NULL,
	PRIMARY KEY (uuid),
	FOREIGN KEY (pub_key_uuid) REFERENCES pub_key (uuid)
);

--
-- Full-text index on User ID text
--
CREATE INDEX user_id_tsindex_idx ON user_id USING gin(ts);

