
const CreateTable_OpenpgpKey = ```
CREATE TABLE openpgp_key IF NOT EXISTS (
--
uuid TEXT,             -- Universally-unique identifer
creation TIMESTAMP,    -- Public key creation timestamp
expiration TIMESTAMP,  -- Public key expiration timestamp (if any)
state INTEGER,         -- State flag for this record
packet bytea           -- Binary contents of the OpenPGP packet
--
rfingerprint TEXT,     -- Full public key fingerprint, LSB-to-MSB, in lowercased hex
selfsig_uuid TEXT,     -- Self-signature
ctime TIMESTAMP,       -- Creation time of this public key fingerprint in the database
mtime TIMESTAMP,       -- Last-modified time of this public key fingerprint in the database
digest TEXT,           -- Content-unique digest of this public key's contents
)
```

const CreateTable_OpenpgpSubkey = ```
CREATE TABLE openpgp_subkey IF NOT EXISTS (
--
uuid TEXT,             -- Universally-unique identifer
creation TIMESTAMP,    -- Public key creation timestamp
expiration TIMESTAMP,  -- Public key expiration timestamp (if any)
state INTEGER,         -- State flag for this record
packet bytea           -- Binary contents of the OpenPGP packet
--
rfingerprint TEXT,     -- Subkey fingerprint, LSB-to-MSB, in lowercased hex
key_uuid TEXT,         -- Primary key to which the subkey belongs
selfsig_uuid TEXT,     -- Self-signature made by the primary on this subkey
crosssig_uuid TEXT,    -- Cross-signaure made by the subkey on the primary, if possible
)
```

const CreateTable_OpenpgpSig = ```
CREATE TABLE openpgp_sig IF NOT EXISTS (
--
uuid TEXT,             -- Universally-unique identifer
creation TIMESTAMP,    -- Signature creation timestamp
expiration TIMESTAMP,  -- Signature expiration timestamp (if any)
state INTEGER,         -- State flag for this record
packet bytea           -- Binary contents of the OpenPGP packet
--
signer TEXT            -- Key ID (16-character prefix of the public key rfingerprint)
signer_uuid TEXT       -- Reference to the signer in this database
)
```

const CreateTable_OpenpgpSigTrust = ```
CREATE TABLE openpgp_sig_trust IF NOT EXISTS (
sig_uuid TEXT,
trust_level INTEGER,
trust_amount INTEGER
)
```

const CreateTable_OpenpgpUid = ```
CREATE TABLE openpgp_uid IF NOT EXISTS (
--
uuid TEXT,             -- Universally-unique identifer
creation TIMESTAMP,    -- Signature creation timestamp
expiration TIMESTAMP,  -- Signature expiration timestamp (if any)
state INTEGER,         -- State flag for this record
packet bytea           -- Binary contents of the OpenPGP packet
--
key_uuid TEXT               -- 
keywords TEXT                -- Original text of the user identity string
keywords_fulltext tsvector   -- Tokenized, fulltext searchable index
)
```

const CreateTable_OpenpgpKeySig = ```
CREATE TABLE openpgp_uid_sig IF NOT EXISTS (
--
uuid TEXT,             -- Universally-unique identifer
creation TIMESTAMP,    -- Signature creation timestamp
expiration TIMESTAMP,  -- Signature expiration timestamp (if any)
state INTEGER,         -- State flag for this record
--
uid_uuid TEXT,
sig_uuid TEXT
)
```

const CreateTable_OpenpgpUidSig = ```
CREATE TABLE openpgp_uid_sig IF NOT EXISTS (
--
uuid TEXT,             -- Universally-unique identifer
creation TIMESTAMP,    -- Signature creation timestamp
expiration TIMESTAMP,  -- Signature expiration timestamp (if any)
state INTEGER,         -- State flag for this record
--
uid_uuid TEXT,         -- UID that is signed
sig_uuid TEXT,         -- Signature
rev_uuid TEXT          -- Signature revocation
)
```

const CreateTable_PrefixTree = ```
CREATE TABLE prefix_tree IF NOT EXISTS (
)
```
