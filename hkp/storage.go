package hkp

// Queryer defines the storage API for search and retrieval of public key material.
type Queryer interface {

	// MatchMD5 returns the matching RFingerprint IDs for the given public key MD5 hashes.
	// The MD5 is calculated using the "SKS method".
	MatchMD5([]string) ([]RFingerprint, error)

	// MatchID returns the matching RFingerprint IDs for the given public key IDs.
	// Key IDs may be short (last 4 bytes), long (last 10 bytes) or full (20 byte)
	// hexadecimal key IDs.
	Resolve([]string) ([]RFingerprint, error)

	// MatchKeyword returns the matching RFingerprint IDs for the given keyword search.
	// The keyword search is storage dependant and results may vary among
	// different implementations.
	MatchKeyword([]string) ([]RFingerprint, error)

	// FetchKeys returns the public key packet models matching the given RFingerprint slice.
	FetchKeys([]RFingerprint) ([]*Pubkey, error)
}

// Inserter defines the storage API for inserting key material.
type Inserter interface {

	// Insert inserts new public keys if they are not already stored. If they
	// are, then nothing is changed.
	Insert([]*Pubkey) error
}

// Updater defines the storage API for writing key material.
type Updater interface {
	Inserter

	// UpdatePubkey updates the stored Pubkey with the given contents.
	UpdatePubkey(*Pubkey)

	// UpdateSubkey updates the stored Subkey with the given contents.
	UpdateSubkey(*Subkey)

	// UpdateUserID updates the stored UserID with the given contents.
	UpdateUserID(*UserID)

	// UpdateUserAttribute updates the stored UserAttribute with the given contents.
	UpdateUserAttribute(*UserAttribute)

	// UpdateSignature updates the stored Signature with the given contents.
	UpdateSignature(*Signature)
}

// Storage defines the API that is needed to implement a complete storage
// backend for an HKP service.
type Storage interface {
	Queryer
	Updater
}