// boltuserdb.go - BoltDB backed Katzenpost server user database.
// Copyright (C) 2017  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package boltuserdb implements the Katzenpost server user database with a
// simple boltdb based backend.
package boltuserdb

import (
	"crypto/subtle"
	"fmt"

	bolt "github.com/coreos/bbolt"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/server/userdb"
)

const usersBucket = "users"

type boltUserDB struct {
	db *bolt.DB
}

func (d *boltUserDB) IsValid(u []byte, k *ecdh.PublicKey) bool {
	// Reject pathologically malformed arguments.
	if u == nil || len(u) > userdb.MaxUsernameSize || k == nil {
		return false
	}

	// Query the database to see if the user is present, and if the public
	// keys match.
	isValid := false
	if err := d.db.View(func(tx *bolt.Tx) error {
		// Grab the `users` bucket.
		bkt := tx.Bucket([]byte(usersBucket))
		if bkt == nil {
			panic("BUG: userdb: `users` bucket is missing")
		}

		// If the user exists in the `users` bucket, then compare public keys.
		rawPubKey := bkt.Get(u)
		if rawPubKey != nil {
			isValid = subtle.ConstantTimeCompare(rawPubKey, k.Bytes()) == 1
		}
		return nil
	}); err != nil {
		return false
	}

	return isValid
}

func (d *boltUserDB) Add(u []byte, k *ecdh.PublicKey) error {
	if u == nil || len(u) > userdb.MaxUsernameSize {
		return fmt.Errorf("userdb: invalid username: `%v`", u)
	}
	if k == nil {
		return fmt.Errorf("userdb: must provide a public key")
	}

	err := d.db.Update(func(tx *bolt.Tx) error {
		// Grab the `users` bucket.
		bkt := tx.Bucket([]byte(usersBucket))
		if bkt == nil {
			panic("BUG: userdb: `users` bucket is missing")
		}

		// And add or update the user's entry.
		return bkt.Put(u, k.Bytes())
	})
	return err
}

func (d *boltUserDB) Close() {
	d.db.Sync()
	d.db.Close()
}

// New creates (or loads) a user database with the given file name f.
func New(f string) (userdb.UserDB, error) {
	const (
		metadataBucket = "metadata"
		versionKey     = "version"
	)

	var err error

	d := new(boltUserDB)
	d.db, err = bolt.Open(f, 0600, nil)
	if err != nil {
		return nil, err
	}

	if err = d.db.Update(func(tx *bolt.Tx) error {
		// Ensure that all the buckets exists, and grab the metadata bucket.
		bkt, err := tx.CreateBucketIfNotExists([]byte(metadataBucket))
		if err != nil {
			return err
		}
		if _, err = tx.CreateBucketIfNotExists([]byte(usersBucket)); err != nil {
			return err
		}

		if b := bkt.Get([]byte(versionKey)); b != nil {
			// Well it looks like we loaded as opposed to created.
			if len(b) != 1 || b[0] != 0 {
				return fmt.Errorf("userdb: incompatible version: %d", uint(b[0]))
			}
			return nil
		}

		// We created a new database, so populate the new `metadata` bucket.
		bkt.Put([]byte(versionKey), []byte{0})

		return nil
	}); err != nil {
		// The struct isn't getting returned so clean up the database.
		d.db.Close()
		return nil, err
	}

	return d, nil
}
