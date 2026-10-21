package sniffer

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func clientHelloWithECH(serverName string) []byte {
	hello := makeTestClientHello(serverName, 0)
	const extensionsOffset = 47
	extensions := append([]byte(nil), hello[extensionsOffset:]...)
	extensions = append(extensions, 0xfe, 0x0d, 0, 0) // ECH extension type with empty test payload
	hello = append(append([]byte(nil), hello[:extensionsOffset]...), extensions...)
	binary.BigEndian.PutUint16(hello[45:47], uint16(len(extensions)))
	bodyLength := len(hello) - tlsHandshakeHeaderLen
	hello[1] = byte(bodyLength >> 16)
	hello[2] = byte(bodyLength >> 8)
	hello[3] = byte(bodyLength)
	return hello
}

func TestSniffTLSInfoWaitsForAllExtensionsAndDetectsECH(t *testing.T) {
	plainHello := makeTestClientHello("example.com", 0)
	plainInfo, err := SniffTLSInfo(makeTestTLSRecords(plainHello))
	require.NoError(t, err)
	require.Equal(t, "example.com", plainInfo.ServerName)
	require.False(t, plainInfo.HasECH)

	echHello := clientHelloWithECH("example.com")
	echInfo, err := SniffTLSInfo(makeTestTLSRecords(echHello))
	require.NoError(t, err)
	require.Equal(t, "example.com", echInfo.ServerName)
	require.True(t, echInfo.HasECH)

	// The legacy SniffTLS API can return SNI as soon as that extension is
	// complete. The stricter MITM API must wait for later extensions to know
	// whether ECH is present.
	sniEnd := tlsRecordHeaderLen + 47 + len(makeTestClientHello("example.com", 0)[47:])
	partial := makeTestTLSRecords(echHello)[:sniEnd]
	legacyName, err := SniffTLS(partial)
	require.NoError(t, err)
	require.Equal(t, "example.com", *legacyName)
	_, err = SniffTLSInfo(partial)
	require.ErrorIs(t, err, ErrNoClue)
}

func TestSniffTLSInfoAcrossRecords(t *testing.T) {
	hello := clientHelloWithECH("segmented.example")
	wire := makeTestTLSRecords(hello, 3, 29, len(hello)/2)
	info, err := SniffTLSInfo(wire)
	require.NoError(t, err)
	require.Equal(t, "segmented.example", info.ServerName)
	require.True(t, info.HasECH)
}
