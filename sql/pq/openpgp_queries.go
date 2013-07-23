package pq

const Query_OpenpgpUid_Keyword = `
SELECT DISTINCT(pubkey_uuid)
FROM openpgp_uid
WHERE keywords_fulltext @@ to_tsquery($1) LIMIT $2
`

const Query_Openpgp_ShortId = `
SELECT pubkey_uuid
FROM openpgp_pubkey
WHERE rfingerprint LIKE $1 || '________________________________'
`

const Query_Openpgp_LongId = `
SELECT pubkey_uuid
FROM openpgp_pubkey
WHERE rfingerprint LIKE $1 || '________________________'
`

const Query_Openpgp_Fingerprint = `
SELECT pubkey_uuid
FROM openpgp_pubkey
WHERE rfingerprint = $1
`

const Query_OpenpgpKey = `
SELECT bytea FROM (
SELECT bytea, 1 as type, uuid FROM openpgp_pubkey pk WHERE uuid = $1 UNION
SELECT bytea, 1 as type, pksig.pubkey_uuid FROM openpgp_sig sig
  JOIN openpgp_pubkey_sig pksig ON (sig.uuid = pksig.sig_uuid)
  WHERE pksig.pub_uuid = $1 UNION
SELECT bytea, 2 as type, uuid FROM openpgp_subkey sk WHERE pubkey_uuid = $1 UNION
SELECT bytea, 2 as type, sksig.subkey_uuid FROM openpgp_sig sig
  JOIN openpgp_subkey_sig sksig ON (sig.uuid = sksig.sig_uuid)
  JOIN openpgp_subkey sk ON (sksig.subkey_uuid = sk.uuid)
  WHERE sk.pub_uuid = $1 UNION
SELECT bytea, 3 as type, uid.uuid FROM openpgp_uid WHERE pubkey_uuid = $1 UNION
SELECT bytea, 3 as type, uidsig.uid_uuid FROM openpgp_uid uid
  JOIN openpgp_uid_sig uidsig ON (uid.uuid = uidsig.uid_uuid)
  WHERE uid.pubkey_uuid = $1 UNION
SELECT bytea, 3 as type, uat.uuid FROM openpgp_uat WHERE pubkey_uuid = $1 UNION
SELECT bytea, 3 as type, uatsig.uat_uuid FROM openpgp_uat uat
  JOIN openpgp_uat_sig uatsig ON (uat.uuid = uatsig.uat_uuid)
  WHERE uat.pubkey_uuid = $1) ORDER BY type, creation, uuid
`

const Insert_Openpgp_NewKey = `
INSERT INTO openpgp_pubkey (
uuid, creation, expiration, state, packet,
ctime, mtime, md5, sha256,
rfingerprint, algorithm, bit_len)
VALUES (
$1, $2, $3, $4, $5,
now(), now(), $6, $7,
$8, $9, $10)
`

const Update_Openpgp_Pubkey = `
UPDATE openpgp_pubkey SET

const Update_Openpgp_RevPubKey = `
UPDATE openpgp_pubkey pk SET rev_uuid = (
  SELECT sig.uuid FROM openpgp_sig sig
    JOIN openpgp_pubkey_sig pksig ON (sig.uuid = pksig.sig_uuid)
  WHERE sig_type = 0x20 AND pksig.pubkey_uuid = pk.uuid)
WHERE pk.rev_uuid IS NULL
`
