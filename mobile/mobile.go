// Package mobile provides a gomobile-compatible API for olcRTC.
// Build with: gomobile bind -target=android ./mobile
package mobile

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/client"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/openlibrecommunity/olcrtc/internal/protect"
	"github.com/openlibrecommunity/olcrtc/internal/runtimecfg"

	_ "golang.org/x/mobile/bind" // ensure gomobile bind is available
)

// SocketProtector protects sockets from VPN routing on Android.
// Implement this interface in Kotlin/Java and pass to SetProtector.
type SocketProtector interface {
	Protect(fd int) bool
}

// LogWriter receives log messages from olcRTC.
type LogWriter interface {
	WriteLog(msg string)
}

var (
	errAlreadyRunning      = errors.New("olcRTC already running")
	errProviderRequired    = errors.New("provider is required")
	errUnsupportedProvider = errors.New("unsupported provider")
	errRoomIDRequired      = errors.New("roomID is required")
	errKeyHexRequired      = errors.New("keyHex is required")
	errNotRunning          = errors.New("olcRTC is not running")
	errStoppedBeforeReady  = errors.New("olcRTC stopped before becoming ready")
	errStartTimedOut       = errors.New("olcRTC start timed out")
)

// Runtime exposes the singleton olcRTC mobile lifecycle via gomobile-friendly instance methods.
// Multiple Runtime instances share the same underlying process state.
type Runtime struct{}

// NewRuntime creates a gomobile-bindable runtime handle.
func NewRuntime() *Runtime {
	return &Runtime{}
}

// SetProtector sets the Android VPN socket protector.
func (r *Runtime) SetProtector(p SocketProtector) {
	SetProtector(p)
}

// SetLogWriter sets a custom log writer for olcRTC output.
func (r *Runtime) SetLogWriter(w LogWriter) {
	SetLogWriter(w)
}

// SetDebug enables or disables verbose logging.
func (r *Runtime) SetDebug(enabled bool) {
	SetDebug(enabled)
}

// Start launches the olcRTC client in background.
func (r *Runtime) Start(providerName, roomID, keyHex string, socksPort int, socksUser, socksPass string) error {
	return Start(providerName, roomID, keyHex, socksPort, socksUser, socksPass)
}

// WaitReady blocks until the selected provider is connected and the local SOCKS5 listener is ready.
func (r *Runtime) WaitReady(timeoutMillis int) error {
	return WaitReady(timeoutMillis)
}

// Stop gracefully stops the olcRTC client.
func (r *Runtime) Stop() {
	Stop()
}

// IsRunning returns true if the olcRTC client is active.
func (r *Runtime) IsRunning() bool {
	return IsRunning()
}

//nolint:gochecknoglobals // Mobile bindings expose a singleton runtime controlled by the embedding app.
var (
	mu           sync.Mutex
	cancel       context.CancelFunc
	done         chan struct{}
	ready        chan struct{}
	errRun       error
	registerOnce sync.Once
)

// SetProtector sets the Android VPN socket protector.
// Must be called before Start.
func SetProtector(p SocketProtector) {
	if p == nil {
		protect.Protector = nil
		return
	}
	protect.Protector = func(fd int) bool {
		return p.Protect(fd)
	}
}

// SetLogWriter sets a custom log writer for olcRTC output.
func SetLogWriter(w LogWriter) {
	if w != nil {
		log.SetOutput(&logBridge{w: w})
	}
}

// SetDebug enables or disables verbose logging.
func SetDebug(enabled bool) {
	logger.SetVerbose(enabled)
	if enabled {
		log.SetFlags(log.Ltime | log.Lshortfile)
		return
	}

	log.SetFlags(log.Ltime)
}

// Start launches the olcRTC client in background.
// providerName: provider identifier (`telemost`, `jazz`, or `salutejazz` alias)
// roomID: provider-specific session identifier
// keyHex: 64-char hex encryption key
// socksPort: local SOCKS5 proxy port (e.g. 10808)
// socksUser/socksPass: SOCKS5 credentials (empty = no auth).
func Start(providerName, roomID, keyHex string, socksPort int, socksUser, socksPass string) error {
	registerOnce.Do(runtimecfg.RegisterProviders)
	providerName = runtimecfg.NormalizeProviderName(providerName)

	mu.Lock()
	defer mu.Unlock()

	switch {
	case cancel != nil:
		return errAlreadyRunning
	case providerName == "":
		return errProviderRequired
	case !runtimecfg.IsSupportedProvider(providerName):
		return errUnsupportedProvider
	case roomID == "":
		return errRoomIDRequired
	case keyHex == "":
		return errKeyHexRequired
	}

	roomURL := runtimecfg.BuildRoomURL(providerName, roomID)

	ctx, cancelFunc := context.WithCancel(context.Background())
	cancel = cancelFunc
	done = make(chan struct{})
	ready = make(chan struct{})
	localReady := ready
	errRun = nil

	var readyOnce sync.Once
	go func() {
		defer cancelFunc()

		err := client.RunWithReady(
			ctx,
			providerName,
			roomURL,
			keyHex,
			socksPort,
			"",
			socksUser,
			socksPass,
			func() {
				readyOnce.Do(func() {
					close(localReady)
				})
			},
		)

		mu.Lock()
		cancel = nil
		errRun = err
		mu.Unlock()
		close(done)
	}()

	return nil
}

// WaitReady blocks until the selected provider peers are connected and the local SOCKS5 listener is ready.
//
//nolint:cyclop // The control flow is intentionally linear so mobile callers can observe each startup state clearly.
func WaitReady(timeoutMillis int) error {
	mu.Lock()
	r := ready
	d := done
	runErr := errRun
	running := cancel != nil
	mu.Unlock()

	if r == nil {
		if runErr != nil {
			return runErr
		}

		return errNotRunning
	}

	select {
	case <-r:
		return nil
	default:
	}

	if !running {
		if runErr != nil {
			return runErr
		}

		return errStoppedBeforeReady
	}

	timer := time.NewTimer(time.Duration(timeoutMillis) * time.Millisecond)
	defer timer.Stop()

	select {
	case <-r:
		return nil
	case <-d:
		mu.Lock()
		runErr = errRun
		mu.Unlock()
		if runErr != nil {
			return runErr
		}

		return errStoppedBeforeReady
	case <-timer.C:
		return errStartTimedOut
	}
}

// Stop gracefully stops the olcRTC client.
func Stop() {
	mu.Lock()
	cancelFunc := cancel
	doneCh := done
	mu.Unlock()

	if cancelFunc == nil {
		return
	}

	cancelFunc()

	if doneCh != nil {
		<-doneCh
	}
}

// IsRunning returns true if the olcRTC client is active.
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return cancel != nil
}

// logBridge adapts LogWriter to io.Writer for log package.
type logBridge struct {
	w LogWriter
}

func (b *logBridge) Write(p []byte) (int, error) {
	b.w.WriteLog(string(p))
	return len(p), nil
}
