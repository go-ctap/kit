package transport

import (
	"context"
	"errors"

	ctapiso7816 "github.com/go-ctap/ctap/transport/iso7816"
	baseiso7816 "github.com/go-ctap/iso7816"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/pcsc"
)

func discoverSmartCards(ctx context.Context) ([]Descriptor, error) {
	var descriptors []Descriptor
	var probeErr error
	for reader, err := range pcsc.Enumerate() {
		if err != nil {
			return nil, normalizeTransportError(err, failureCodeForSmartCard(err))
		}
		if err := ctx.Err(); err != nil {
			return nil, normalizeTransportError(err, failureCodeForSmartCard(err))
		}
		if reader.State&pcsc.ReaderStatePresent == 0 {
			continue
		}

		supported, err := probeSmartCard(ctx, reader.Name)
		if err != nil {
			if isNonFIDOCard(err) {
				continue
			}

			probeErr = errors.Join(probeErr, err)
			continue
		}
		if !supported {
			continue
		}

		descriptors = append(descriptors, Descriptor{
			Transport: ModeSmartCard,
			Path:      reader.Name,
			Product:   reader.Name,
			ATR:       reader.ATR,
		})
	}

	if len(descriptors) == 0 && probeErr != nil {
		return nil, normalizeTransportError(probeErr, failureCodeForSmartCard(probeErr))
	}

	return descriptors, nil
}

func failureCodeForSmartCard(err error) failure.Code {
	if errors.Is(err, pcsc.ErrNoAccess) {
		return failure.CodeTransportPermissionDenied
	}

	return failure.CodeTransportFailure
}

func probeSmartCard(ctx context.Context, reader string) (bool, error) {
	card, err := pcsc.Open(reader, pcsc.WithShareMode(pcsc.ShareModeExclusive))
	if err != nil {
		return false, err
	}

	transport, err := ctapiso7816.New(ctx, card)
	if err != nil {
		return false, errors.Join(err, card.Close())
	}

	return true, transport.Close()
}

func isNonFIDOCard(err error) bool {
	if errors.Is(err, ctapiso7816.ErrUnsupportedVersion) {
		return true
	}

	_, ok := errors.AsType[*baseiso7816.APDUError](err)
	return ok
}

func smartCardEvents(ctx context.Context) (<-chan Event, error) {
	receiver, err := pcsc.Events()
	if err != nil {
		return nil, normalizeTransportError(err, failureCodeForSmartCard(err))
	}

	events := make(chan Event)
	go func() {
		defer close(events)
		defer func() {
			_ = receiver.Close()
		}()

		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-receiver.Listen():
				if !ok {
					return
				}

				converted := Event{}
				if event.Err != nil {
					converted.Err = normalizeTransportError(
						event.Err,
						failureCodeForSmartCard(event.Err),
					)
				}

				select {
				case events <- converted:
				case <-ctx.Done():
					return
				}
				if event.Err != nil {
					return
				}
			}
		}
	}()

	return events, nil
}
