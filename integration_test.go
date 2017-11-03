// scheduler.go - Katzenpost server integration test
// Copyright (C) 2017  David Stainton.
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
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/katzenpost/server/config"
	"github.com/stretchr/testify/require"
)

func TestClientServerIntegration(t *testing.T) {
	require := require.New(t)

	datadir, err := ioutil.TempDir("", "datadir")
	require.NoError(err, "err")

	const basicConfig = `# A basic configuration example.
[server]
Identifier = "katzenpost.example.com"
Addresses = [ "127.0.0.1:29483" ]
DataDir = "%s"
IsProvider = true

[Logging]
Level = "DEBUG"
`
	cfg, err := config.Load([]byte(fmt.Sprintf(basicConfig, datadir)))
	require.NoError(err, "Load() with basic config")

	server, err := New(cfg)
	require.NoError(err, "error")
	provider, err := newProvider(server)
	require.NoError(err, "error")

	t.Logf("provider %s", provider)
}
