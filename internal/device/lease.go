package device

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-ctap/kit/model/report"
	"github.com/gofrs/flock"
)

const (
	lockNamespace = "ctapkit"
	lockDirName   = "locks"
)

var (
	userCacheDir       = os.UserCacheDir
	lockAcquireTimeout = 25 * time.Millisecond
	lockRetryDelay     = 5 * time.Millisecond
)

// Lease represents exclusive access to one authenticator identity.
type Lease struct {
	key  string
	path string
	lock *flock.Flock

	once sync.Once
	err  error
}

func AcquireLease(ctx context.Context, selected report.DeviceReport) (*Lease, error) {
	key := Key(selected.VendorID, selected.ProductID, selected.Serial, selected.Path)

	path, err := lockPath(key)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}

	lock := flock.New(path)

	attemptCtx, cancel := context.WithTimeout(ctx, lockAcquireTimeout)
	defer cancel()

	locked, err := lock.TryLockContext(attemptCtx, lockRetryDelay)
	if locked {
		return &Lease{key: key, path: path, lock: lock}, nil
	}

	_ = lock.Close()

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}

		return nil, fmt.Errorf("%w: %s", ErrBusy, selected.DeviceID)
	}

	return nil, err
}

func (l *Lease) Close() error {
	l.once.Do(func() {
		l.err = l.lock.Unlock()
		l.lock = nil
	})

	return l.err
}

func (l *Lease) Path() string {
	return l.path
}

func lockPath(key string) (string, error) {
	cacheDir, err := userCacheDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(cacheDir, lockNamespace, lockDirName, key+".lock"), nil
}
