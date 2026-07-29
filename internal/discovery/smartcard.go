package discovery

import (
	"context"
	"errors"
	"sync"

	ctapiso7816 "github.com/go-ctap/ctap/transport/iso7816"
	baseiso7816 "github.com/go-ctap/iso7816"
	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/transport"
	"github.com/go-ctap/pcsc"
)

type smartCardDiscovery struct {
	mu        sync.Mutex
	supported map[smartCardAttachment]Descriptor
}

type smartCardAttachment struct {
	reader string
	atr    string
}

type smartCardProbeFunc func(context.Context, string) (transport.SmartCardInterface, error)

func (d *Discovery) discoverSmartCards(ctx context.Context) ([]Descriptor, error) {
	readers, err := enumerateSmartCardReaders(ctx)
	if err != nil {
		return nil, err
	}

	return d.smartCards.discover(ctx, readers, probeSmartCard)
}

func enumerateSmartCardReaders(ctx context.Context) ([]pcsc.ReaderInfo, error) {
	var readers []pcsc.ReaderInfo
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

		readers = append(readers, pcsc.ReaderInfo{
			Name:  reader.Name,
			State: reader.State,
			ATR:   append([]byte(nil), reader.ATR...),
		})
	}

	return readers, nil
}

func (d *smartCardDiscovery) discover(
	ctx context.Context,
	readers []pcsc.ReaderInfo,
	probe smartCardProbeFunc,
) ([]Descriptor, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	nextSupported := make(map[smartCardAttachment]Descriptor)
	var descriptors []Descriptor
	var probeErr error
	for _, reader := range readers {
		if err := ctx.Err(); err != nil {
			return nil, normalizeTransportError(err, failureCodeForSmartCard(err))
		}

		attachment := smartCardAttachment{
			reader: reader.Name,
			atr:    string(reader.ATR),
		}
		cached, wasSupported := d.supported[attachment]
		if !wasSupported && len(reader.ATR) == 0 {
			attachment, cached, wasSupported = d.supportedByReader(reader.Name)
		}
		if wasSupported && reader.State&pcsc.ReaderStateExclusive != 0 {
			nextSupported[attachment] = cached
			descriptors = append(descriptors, cached)

			continue
		}

		cardInterface, err := probe(ctx, reader.Name)
		if err != nil {
			if isNonFIDOCard(err) {
				continue
			}
			if wasSupported && errors.Is(err, pcsc.ErrSharingViolation) {
				nextSupported[attachment] = cached
				descriptors = append(descriptors, cached)

				continue
			}

			probeErr = errors.Join(probeErr, err)
			continue
		}

		descriptor := smartCardDescriptor(reader, cardInterface)
		nextSupported[attachment] = descriptor
		descriptors = append(descriptors, descriptor)
	}
	d.supported = nextSupported

	if len(descriptors) == 0 && probeErr != nil {
		return nil, normalizeTransportError(probeErr, failureCodeForSmartCard(probeErr))
	}

	return descriptors, nil
}

func (d *smartCardDiscovery) supportedByReader(reader string) (
	smartCardAttachment,
	Descriptor,
	bool,
) {
	for attachment, descriptor := range d.supported {
		if attachment.reader == reader {
			return attachment, descriptor, true
		}
	}

	return smartCardAttachment{}, Descriptor{}, false
}

func smartCardDescriptor(
	reader pcsc.ReaderInfo,
	cardInterface transport.SmartCardInterface,
) Descriptor {
	return Descriptor{
		Transport:          ModeSmartCard,
		Path:               reader.Name,
		ATR:                reader.ATR,
		SmartCardInterface: cardInterface,
	}
}

func failureCodeForSmartCard(err error) failure.Code {
	if errors.Is(err, pcsc.ErrNoAccess) {
		return failure.CodeTransportPermissionDenied
	}

	return failure.CodeTransportFailure
}

func probeSmartCard(
	ctx context.Context,
	reader string,
) (transport.SmartCardInterface, error) {
	// A probe owns this connection and must leave no pending applet state behind
	// when it releases the card.
	card, err := pcsc.Open(
		reader,
		pcsc.WithShareMode(pcsc.ShareModeExclusive),
		pcsc.WithDisconnectDisposition(pcsc.DispositionResetCard),
	)
	if err != nil {
		return "", err
	}

	cardInterface := smartCardInterface(card.Interface())
	t, err := ctapiso7816.New(ctx, card)
	if err != nil {
		return "", errors.Join(err, card.Close())
	}

	// Successful applet selection already proves support. Cleanup failure does
	// not invalidate that result and there is no owned resource to return.
	_ = t.Close()

	return cardInterface, nil
}

func smartCardInterface(value pcsc.CardInterface) transport.SmartCardInterface {
	switch value {
	case pcsc.CardInterfaceContact:
		return transport.SmartCardInterfaceContact
	case pcsc.CardInterfaceContactless:
		return transport.SmartCardInterfaceContactless
	default:
		return transport.SmartCardInterfaceUnknown
	}
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
