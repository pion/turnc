package turnc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gortc/turn"

	"github.com/pion/logging"

	"github.com/pion/stun"
)

// Channel implements net.PacketConn.
type Channel struct {
	log          logging.LeveledLogger
	mux          sync.RWMutex
	number       turn.ChannelNumber
	peerAddr     turn.PeerAddress
	peerL, peerR net.Conn
	client       *Client
	ctx          context.Context
	cancel       func()
	wg           sync.WaitGroup
	refreshRate  time.Duration
}

// Read data from peer.
func (ch *Channel) Read(b []byte) (n int, err error) {
	return ch.peerR.Read(b)
}

// Bound returns true if channel number is bound for current permission.
func (ch *Channel) Bound() bool {
	ch.mux.RLock()
	defer ch.mux.RUnlock()
	return ch.number.Valid()
}

// Binding returns current channel number or 0 if not bound.
func (ch *Channel) Binding() turn.ChannelNumber {
	ch.mux.RLock()
	defer ch.mux.RUnlock()
	return ch.number
}

var (
	// ErrAlreadyBound means that selected permission already has bound channel number.
	ErrAlreadyBound = errors.New("channel already bound")
	// ErrNotBound means that selected permission already has no channel number.
	ErrNotBound = errors.New("channel is not bound")
)

func (ch *Channel) refresh() error {
	return ch.client.alloc.allocate(ch.peerAddr)
}

func (ch *Channel) startLoop(f func()) {
	if ch.refreshRate == 0 {
		return
	}
	ch.wg.Add(1)
	go func() {
		ticker := time.NewTicker(ch.refreshRate)
		defer ch.wg.Done()
		for {
			select {
			case <-ticker.C:
				f()
			case <-ch.ctx.Done():
				return
			}
		}
	}()
}

func (ch *Channel) startRefreshLoop() {
	ch.startLoop(func() {
		if err := ch.refresh(); err != nil {
			ch.log.Errorf("failed to refresh permission: %v", err)
		}
		ch.log.Debug("permission refreshed")
	})
}

// refreshBind performs rebinding of a channel.
func (ch *Channel) refreshBind() error {
	ch.mux.Lock()
	defer ch.mux.Unlock()
	if ch.number == 0 {
		return ErrNotBound
	}
	if err := ch.bind(ch.number); err != nil {
		return err
	}
	ch.log.Debug("binding refreshed")
	return nil
}

func (ch *Channel) bind(n turn.ChannelNumber) error {
	// Starting transaction.
	a := ch.client.alloc
	res := stun.New()
	req := stun.New()
	req.TransactionID = stun.NewTransactionID()
	req.Type = stun.NewType(stun.MethodChannelBind, stun.ClassRequest)
	req.WriteHeader()
	setters := make([]stun.Setter, 0, 10)
	setters = append(setters, &ch.peerAddr, n)
	if len(a.integrity) > 0 {
		// Applying auth.
		setters = append(setters,
			a.nonce, a.client.username, a.client.realm, a.integrity,
		)
	}
	setters = append(setters, stun.Fingerprint)
	for _, s := range setters {
		if setErr := s.AddTo(req); setErr != nil {
			return setErr
		}
	}
	if doErr := ch.client.do(req, res); doErr != nil {
		return doErr
	}
	if res.Type != stun.NewType(stun.MethodChannelBind, stun.ClassSuccessResponse) {
		return fmt.Errorf("unexpected response type %s", res.Type)
	}
	// Success.
	return nil
}

// Bind performs binding transaction, allocating channel binding for
// the permission.
func (ch *Channel) Bind() error {
	ch.mux.Lock()
	defer ch.mux.Unlock()
	if ch.number != 0 {
		return ErrAlreadyBound
	}
	a := ch.client.alloc
	a.minBound++
	n := a.minBound
	if err := ch.bind(n); err != nil {
		return err
	}
	ch.number = n

	a.client.mux.Lock()
	a.bindingMap[ch.number] = ch
	a.client.mux.Unlock()

	ch.startLoop(func() {
		if err := ch.refreshBind(); err != nil {
			ch.log.Errorf("failed to refresh bind: %v", err)
		}
	})
	return nil
}

// Write sends buffer to peer.
//
// If permission is bound, the ChannelData message will be used.
func (ch *Channel) Write(b []byte) (n int, err error) {
	if n := ch.Binding(); n.Valid() {
		ch.log.Debug("using channel data to write")
		return ch.client.sendChan(b, n)
	}
	ch.log.Debug("using STUN to write")
	return ch.client.sendData(b, &ch.peerAddr)
}

// Close stops all refreshing loops for permission and removes it from
// allocation.
func (ch *Channel) Close() error {
	cErr := ch.peerR.Close()
	ch.mux.Lock()
	cancel := ch.cancel
	ch.mux.Unlock()
	cancel()
	ch.wg.Wait()
	ch.client.alloc.removeChannel(ch)
	return cErr
}

// LocalAddr is relayed address from TURN server.
func (ch *Channel) LocalAddr() net.Addr {
	return turn.Addr(ch.client.alloc.relayed)
}

// RemoteAddr is peer address.
func (ch *Channel) RemoteAddr() net.Addr {
	return turn.Addr(ch.peerAddr)
}

// SetDeadline implements net.Conn.
func (ch *Channel) SetDeadline(t time.Time) error {
	return ch.peerR.SetDeadline(t)
}

// SetReadDeadline implements net.Conn.
func (ch *Channel) SetReadDeadline(t time.Time) error {
	return ch.peerR.SetReadDeadline(t)
}

// ErrNotImplemented means that functionality is not currently implemented,
// but it will be (eventually).
var ErrNotImplemented = errors.New("functionality not implemented")

// SetWriteDeadline implements net.Conn.
func (ch *Channel) SetWriteDeadline(t time.Time) error {
	return ErrNotImplemented
}
