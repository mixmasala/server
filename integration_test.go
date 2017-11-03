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

	"github.com/katzenpost/client/mix_pki"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
	corepki "github.com/katzenpost/core/pki"
	"github.com/katzenpost/server/config"
	"github.com/stretchr/testify/require"
)

type MixDescriptorSecrets struct {
	linkPrivKey  *ecdh.PrivateKey
	epochSecrets map[ecdh.PublicKey]*ecdh.PrivateKey
}

func createMixDescriptor(name string, layer uint8, addresses []string, startEpoch, endEpoch uint64) (*corepki.MixDescriptor, *MixDescriptorSecrets, error) {
	linkPrivKey, err := ecdh.NewKeypair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	mixKeys := make(map[uint64]*ecdh.PublicKey)
	epochSecrets := make(map[ecdh.PublicKey]*ecdh.PrivateKey)
	for i := startEpoch; i < endEpoch+1; i++ {
		mixPrivKey, err := ecdh.NewKeypair(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		mixKeys[i] = mixPrivKey.PublicKey()
		pubKey := mixPrivKey.PublicKey()
		epochSecrets[*pubKey] = mixPrivKey
	}
	secrets := MixDescriptorSecrets{
		linkPrivKey:  linkPrivKey,
		epochSecrets: epochSecrets,
	}
	descriptor := corepki.MixDescriptor{
		Name:       name,
		LinkKey:    linkPrivKey.PublicKey(),
		MixKeys:    mixKeys,
		Addresses:  addresses,
		Layer:      layer,
		LoadWeight: 0,
	}
	return &descriptor, &secrets, nil
}

func newMixPKI(require *require.Assertions) (corepki.Client, map[ecdh.PublicKey]*ecdh.PrivateKey) {
	type testDesc struct {
		Name  string
		Layer int
		IP    string
		Port  int
	}

	test_providers := []testDesc{
		{
			Name:  "acme.com",
			Layer: 0,
			IP:    "127.0.0.1",
			Port:  11240,
		},
		{
			Name:  "nsa.gov",
			Layer: 0,
			IP:    "127.0.0.1",
			Port:  11241,
		},
		{
			Name:  "gchq.uk",
			Layer: 0,
			IP:    "127.0.0.1",
			Port:  11242,
		},
		{
			Name:  "fsb.ru",
			Layer: 0,
			IP:    "127.0.0.1",
			Port:  11243,
		},
	}

	test_mixes := []testDesc{
		{
			Name:  "nsamix101",
			Layer: 1,
			IP:    "127.0.0.1",
			Port:  11234,
		},
		{
			Name:  "nsamix102",
			Layer: 2,
			IP:    "127.0.0.1",
			Port:  112345,
		},
		{
			Name:  "five_eyes",
			Layer: 3,
			IP:    "127.0.0.1",
			Port:  11236,
		},
		{
			Name:  "gchq123",
			Layer: 1,
			IP:    "127.0.0.1",
			Port:  11237,
		},
		{
			Name:  "fsbspy1",
			Layer: 2,
			IP:    "127.0.0.1",
			Port:  11238,
		},
		{
			Name:  "foxtrot2",
			Layer: 3,
			IP:    "127.0.0.1",
			Port:  11239,
		},
	}

	layerMax := uint8(3)
	keysMap := make(map[ecdh.PublicKey]*ecdh.PrivateKey)
	staticPKI := mix_pki.NewStaticPKI()
	startEpoch, _, _ := epochtime.Now()
	providers := []*corepki.MixDescriptor{}
	mixes := []*corepki.MixDescriptor{}
	for _, provider := range test_providers {
		mockAddr := []string{} // XXX fix me?
		descriptor, descriptorSecrets, err := createMixDescriptor(provider.Name, uint8(provider.Layer), mockAddr, startEpoch, startEpoch+3)
		require.NoError(err, "createMixDescriptor errored")
		providers = append(providers, descriptor)
		for pubKey, privKey := range descriptorSecrets.epochSecrets {
			keysMap[pubKey] = privKey
		}
	}
	for _, mix := range test_mixes {
		mockAddr := []string{} // XXX fix me?
		descriptor, descriptorSecrets, err := createMixDescriptor(mix.Name, uint8(mix.Layer), mockAddr, startEpoch, startEpoch+3)
		require.NoError(err, "createMixDescriptor errored")
		mixes = append(mixes, descriptor)
		for pubKey, privKey := range descriptorSecrets.epochSecrets {
			keysMap[pubKey] = privKey
		}
	}

	// for each epoch create a PKI Document and index it by epoch
	for current := startEpoch; current < startEpoch+3+1; current++ {
		pkiDocument := corepki.Document{
			Epoch: current,
		}
		// topology
		pkiDocument.Topology = make([][]*corepki.MixDescriptor, layerMax+1)
		for i := uint8(0); i < layerMax; i++ {
			pkiDocument.Topology[i] = make([]*corepki.MixDescriptor, 0)
		}
		for i := uint8(0); i < layerMax+1; i++ {
			for _, mix := range mixes {
				if mix.Layer == i {
					pkiDocument.Topology[i] = append(pkiDocument.Topology[i], mix)
				}
			}
		}
		// providers
		for _, provider := range providers {
			pkiDocument.Providers = append(pkiDocument.Providers, provider)
		}
		// setup our epoch -> document map
		staticPKI.Set(current, &pkiDocument)
	}
	return staticPKI, keysMap
}

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

	mockPKI, _ := newMixPKI(require)
	server.pki.impl = mockPKI // XXX nope

	provider, err := newProvider(server)
	require.NoError(err, "error")

	t.Logf("provider %s", provider)
}
