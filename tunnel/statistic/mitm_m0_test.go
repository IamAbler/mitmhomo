package statistic

import (
	"errors"
	"io"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

type trackerTestConn struct {
	C.Conn
	readData []byte
	closed   bool
}

func (c *trackerTestConn) Read(p []byte) (int, error) {
	if len(c.readData) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.readData)
	c.readData = c.readData[n:]
	return n, nil
}
func (*trackerTestConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *trackerTestConn) Close() error {
	c.closed = true
	return nil
}
func (*trackerTestConn) Chains() C.Chain               { return C.Chain{"DIRECT"} }
func (*trackerTestConn) ProviderChains() C.Chain       { return nil }
func (*trackerTestConn) AppendToChains(C.ProxyAdapter) {}
func (*trackerTestConn) RemoteDestination() string     { return "origin.example:443" }

func TestTCPTrackerLeavesManagerOnClose(t *testing.T) {
	manager := &Manager{}
	metadata := &C.Metadata{Host: "origin.example"}
	conn := &trackerTestConn{readData: []byte("reply")}
	tracker := NewTCPTracker(conn, manager, metadata, nil, 0, 0, false)
	require.Equal(t, "origin.example:443", metadata.RemoteDst)
	require.Same(t, tracker, manager.Get(tracker.ID()))

	buffer := make([]byte, 5)
	n, err := tracker.Read(buffer)
	require.NoError(t, err)
	require.Equal(t, "reply", string(buffer[:n]))
	_, err = tracker.Write([]byte("request"))
	require.NoError(t, err)
	require.EqualValues(t, 5, tracker.Info().DownloadTotal.Load())
	require.EqualValues(t, 7, tracker.Info().UploadTotal.Load())

	require.NoError(t, tracker.Close())
	require.True(t, conn.closed)
	require.Nil(t, manager.Get(tracker.ID()), "closed connection must be removed from statistics")
}

func TestTCPTrackerClosePropagatesUnderlyingErrorAndLeavesManager(t *testing.T) {
	closeErr := errors.New("close failed")
	conn := &trackerErrorConn{trackerTestConn: trackerTestConn{}, closeErr: closeErr}
	manager := &Manager{}
	tracker := NewTCPTracker(conn, manager, &C.Metadata{Host: "origin.example"}, nil, 0, 0, false)
	require.ErrorIs(t, tracker.Close(), closeErr)
	require.Nil(t, manager.Get(tracker.ID()))
}

type trackerErrorConn struct {
	trackerTestConn
	closeErr error
}

func (c *trackerErrorConn) Close() error { c.closed = true; return c.closeErr }
