// spool.go - Katzenpost server user message spool.
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

// Package spool defines the Katzenpost server user message spool abstract
// interface.
package spool

import "github.com/katzenpost/core/sphinx/constants"

// Spool is the interface provided by all user messgage spool implementations.
type Spool interface {
	// StoreMessage stores a message in the user's spool.
	StoreMessage(user, msg []byte) error

	// StoreSURBReply stores a SURBReply in the user's spool.
	StoreSURBReply(user []byte, id *[constants.SURBIDLength]byte, msg []byte) error

	// Get optionally deletes the first entry in a user's spool, and returns
	// the (new) first entry.  Both messages and SURBReplies may be returned.
	Get(user []byte, advance bool) (msg, surbID []byte, err error)

	// Close closes the Spool instance.
	Close()
}
