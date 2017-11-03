// nodekey.go - Katzenpost server node key store.
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

package server

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/utils"
)

func (s *Server) initIdentity() error {
	const (
		keyFile = "identity.private.pem"
		keyType = "Ed25519 PRIVATE KEY"
	)
	fn := filepath.Join(s.cfg.Server.DataDir, keyFile)

	// Deserialize the key, if it exists.
	if buf, err := ioutil.ReadFile(fn); err == nil {
		defer utils.ExplicitBzero(buf)
		blk, rest := pem.Decode(buf)
		if len(rest) != 0 {
			return fmt.Errorf("trailing garbage after identity private key")
		}
		if blk.Type != keyType {
			return fmt.Errorf("invalid PEM Type: '%v'", blk.Type)
		}
		defer utils.ExplicitBzero(blk.Bytes)

		s.identityKey = new(eddsa.PrivateKey)
		return s.identityKey.FromBytes(blk.Bytes)
	} else if !os.IsNotExist(err) {
		return err
	}

	// No key exists, generate and persist to disk.
	var err error
	s.identityKey, err = eddsa.NewKeypair(rand.Reader)
	if err != nil {
		return err
	}
	blk := &pem.Block{
		Type:  keyType,
		Bytes: s.identityKey.Bytes(),
	}
	return ioutil.WriteFile(fn, pem.EncodeToMemory(blk), fileMode)
}

func (s *Server) initLink() error {
	const (
		keyFile = "link.private.pem"
		keyType = "X25519 PRIVATE KEY"
	)
	fn := filepath.Join(s.cfg.Server.DataDir, keyFile)

	// Deserialize the key, if it exists.
	if buf, err := ioutil.ReadFile(fn); err == nil {
		defer utils.ExplicitBzero(buf)
		blk, rest := pem.Decode(buf)
		if len(rest) != 0 {
			return fmt.Errorf("trailing garbage after link private key")
		}
		if blk.Type != keyType {
			return fmt.Errorf("invalid PEM Type: '%v'", blk.Type)
		}
		defer utils.ExplicitBzero(blk.Bytes)

		s.linkKey = new(ecdh.PrivateKey)
		return s.linkKey.FromBytes(blk.Bytes)
	} else if !os.IsNotExist(err) {
		return err
	}

	// No key exists, generate and persist to disk.
	var err error
	s.linkKey, err = ecdh.NewKeypair(rand.Reader)
	if err != nil {
		return err
	}
	blk := &pem.Block{
		Type:  keyType,
		Bytes: s.linkKey.Bytes(),
	}
	return ioutil.WriteFile(fn, pem.EncodeToMemory(blk), fileMode)
}
