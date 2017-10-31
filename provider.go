// scheduler.go - Katzenpost server provider backend.
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
	"bytes"
	"sync"

	"github.com/eapache/channels"
	"github.com/katzenpost/core/wire"
	"github.com/katzenpost/server/userdb"
	"github.com/katzenpost/server/userdb/boltuserdb"
	"github.com/op/go-logging"
)

type provider struct {
	sync.WaitGroup

	s      *Server
	ch     *channels.InfiniteChannel
	userDB userdb.UserDB
	log    *logging.Logger

	haltCh chan interface{}
}

func (p *provider) halt() {
	close(p.haltCh)
	p.Wait()

	p.ch.Close()
	if p.userDB != nil {
		p.userDB.Close()
		p.userDB = nil
	}
}

func (p *provider) authenticateClient(c *wire.PeerCredentials) bool {
	p.Add(1)
	defer p.Done()

	isValid := p.userDB.IsValid(c.AdditionalData, c.PublicKey)
	p.log.Debugf("Auth: User: '%v', Key: '%v': %v", asciiBytesToPrintString(c.AdditionalData), ecdhToPrintString(c.PublicKey), isValid)
	return isValid
}

func (p *provider) onPacket(pkt *packet) {
	ch := p.ch.In()
	ch <- pkt
}

func (p *provider) worker() {
	defer func() {
		p.log.Debugf("Halting Provider worker.")
		p.Done()
	}()

	ch := p.ch.Out()

	for {
		var pkt *packet
		select {
		case <-p.haltCh:
			p.log.Debugf("Terminating gracefully.")
		case e := <-ch:
			pkt = e.(*packet)
		}

		// Fix the recipient by trimming off the trailing NUL bytes.
		recipient := bytes.Trim(pkt.recipient.ID[:], "\x00")

		// Ensure the packet is for a valid recipient.
		if !p.userDB.Exists(recipient) {
			p.log.Debugf("Dropping packet: %v (Invalid Recipient: '%v')", pkt.id, asciiBytesToPrintString(recipient))
			pkt.dispose()
			continue
		}

		// XXX/provider: Implement the rest.
		panic("BUG: Provider inbound packet processing is incomplete")
	}
}

func newProvider(s *Server) (*provider, error) {
	p := new(provider)
	p.s = s
	p.ch = channels.NewInfiniteChannel()
	p.log = s.newLogger("provider")
	p.haltCh = make(chan interface{})

	var err error
	p.userDB, err = boltuserdb.New(p.s.cfg.Provider.UserDB)
	if err != nil {
		return nil, err
	}

	p.Add(1)
	go p.worker()
	return p, nil
}
