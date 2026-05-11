package service

import (
	"context"
	"errors"
	"sync"
	"time"

	ctapkit "github.com/go-ctap/kit"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/transport"
	"github.com/google/uuid"
)

type EventEmitter interface {
	Emit(name string, payload any)
}

type Option func(*Service)

type Service struct {
	mu                sync.RWMutex
	emitter           EventEmitter
	strictPermissions bool

	devices      []ctapkit.Device
	sessions     map[SessionID]*managedSession
	operations   map[OperationID]*operationState
	interactions map[InteractionID]*pendingInteraction
}

type managedSession struct {
	id      SessionID
	session *ctapkit.Session

	mu              sync.RWMutex
	activeOperation OperationID
	openedAt        time.Time
	updatedAt       time.Time
}

type operationState struct {
	id     OperationID
	cancel context.CancelFunc
	done   chan struct{}
}

type pendingInteraction struct {
	prompt   InteractionPrompt
	response chan model.InteractionResponse
}

func New(opts ...Option) *Service {
	service := &Service{
		sessions:     make(map[SessionID]*managedSession),
		operations:   make(map[OperationID]*operationState),
		interactions: make(map[InteractionID]*pendingInteraction),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(service)
		}
	}

	return service
}

func WithStrictPermissions(strict bool) Option {
	return func(service *Service) {
		service.strictPermissions = strict
	}
}

func WithEventEmitter(emitter EventEmitter) Option {
	return func(service *Service) {
		service.emitter = emitter
	}
}

func (s *Service) Close() error {
	s.mu.Lock()
	sessions := make([]*managedSession, 0, len(s.sessions))
	for id, session := range s.sessions {
		sessions = append(sessions, session)
		delete(s.sessions, id)
	}

	for id, operation := range s.operations {
		operation.cancel()
		close(operation.done)
		delete(s.operations, id)
	}
	s.mu.Unlock()

	var closeErr error
	for _, session := range sessions {
		if err := session.session.Close(); err != nil {
			closeErr = errors.Join(closeErr, err)
		}
	}

	return closeErr
}

func (s *Service) Discover(ctx context.Context, req DiscoverRequest) (DiscoverySnapshot, error) {
	opts := discoverOptions(req)

	devices, err := ctapkit.DiscoverDevices(ctx, opts...)
	if err != nil {
		return DiscoverySnapshot{}, err
	}

	s.mu.Lock()
	s.devices = devices
	s.mu.Unlock()

	return DiscoverySnapshot{Devices: deviceReports(devices)}, nil
}

func (s *Service) OpenSession(ctx context.Context, req OpenSessionRequest) (SessionSnapshot, error) {
	device, err := s.selectDevice(ctx, req.Selector)
	if err != nil {
		return SessionSnapshot{}, err
	}

	sessionID := newSessionID()
	opts := []ctapkit.OpenSessionOption{
		ctapkit.WithEventSink(sessionEventSink{service: s, sessionID: sessionID}),
	}
	if s.strictPermissions {
		opts = append(opts, ctapkit.WithStrictPermissions())
	}

	session, err := ctapkit.OpenSession(ctx, device, opts...)
	if err != nil {
		return SessionSnapshot{}, err
	}

	now := time.Now().UTC()
	managed := &managedSession{
		id:        sessionID,
		session:   session,
		openedAt:  now,
		updatedAt: now,
	}

	s.mu.Lock()
	s.sessions[managed.id] = managed
	s.mu.Unlock()

	return managed.snapshot(), nil
}

func (s *Service) Sessions(ctx context.Context) ([]SessionSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	snapshots := make([]SessionSnapshot, 0, len(s.sessions))
	for _, session := range s.sessions {
		snapshots = append(snapshots, session.snapshot())
	}

	return snapshots, nil
}

func (s *Service) Session(ctx context.Context, id SessionID) (SessionSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return SessionSnapshot{}, err
	}

	session, ok := s.session(id)
	if !ok {
		return SessionSnapshot{}, invalidSessionError()
	}

	return session.snapshot(), nil
}

func (s *Service) CloseSession(ctx context.Context, id SessionID) (SessionSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return SessionSnapshot{}, err
	}

	s.mu.Lock()
	session, ok := s.sessions[id]
	if ok {
		delete(s.sessions, id)
	}
	s.mu.Unlock()

	if !ok {
		return SessionSnapshot{}, invalidSessionError()
	}

	err := session.session.Close()
	session.touch()

	return session.snapshot(), err
}

func (s *Service) CloseAllSessions(ctx context.Context) ([]SessionSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	sessions := make([]*managedSession, 0, len(s.sessions))
	for id, session := range s.sessions {
		sessions = append(sessions, session)
		delete(s.sessions, id)
	}
	s.mu.Unlock()

	snapshots := make([]SessionSnapshot, 0, len(sessions))
	var closeErr error
	for _, session := range sessions {
		if err := session.session.Close(); err != nil {
			closeErr = errors.Join(closeErr, err)
		}
		session.touch()

		snapshot := session.snapshot()
		snapshots = append(snapshots, snapshot)
	}

	return snapshots, closeErr
}

func (s *Service) runOperation(ctx context.Context, req OperationRequest, operation model.Operation) (OperationEnvelope, error) {
	session, ok := s.session(req.SessionID)
	if !ok {
		return OperationEnvelope{}, invalidSessionError()
	}

	if operation == nil {
		return OperationEnvelope{}, invalidOperationError("operation is required")
	}

	operationID := newOperationID()
	ctx, cancel := context.WithCancel(ctx)
	state := &operationState{
		id:     operationID,
		cancel: cancel,
		done:   make(chan struct{}),
	}

	s.registerOperation(state)
	session.setActiveOperation(operationID)
	defer cancel()
	defer session.setActiveOperation("")
	defer s.unregisterOperation(operationID)

	opts := runOptions(req.VerificationFlow)
	result, err := session.session.Run(ctx, operation, interactionHandler{
		service:     s,
		sessionID:   req.SessionID,
		operationID: operationID,
	}, opts...)

	envelope := OperationEnvelope{
		OperationID: operationID,
		SessionID:   req.SessionID,
		Kind:        operation.Kind(),
		Result:      result,
		Error:       runtimeErrorEnvelope(err),
	}

	return envelope, err
}

func (s *Service) CancelOperation(ctx context.Context, req CancelOperationRequest) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	s.mu.RLock()
	operation, ok := s.operations[req.OperationID]
	s.mu.RUnlock()

	if !ok {
		return false, nil
	}

	operation.cancel()

	return true, nil
}

func (s *Service) ResolveInteraction(ctx context.Context, answer InteractionAnswer) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	s.mu.Lock()
	pending, ok := s.interactions[answer.InteractionID]
	if ok {
		delete(s.interactions, answer.InteractionID)
	}
	s.mu.Unlock()

	if !ok {
		return false, nil
	}

	response := model.InteractionResponse{
		PIN:       []byte(answer.PIN),
		Confirmed: answer.Confirmed,
		Canceled:  answer.Canceled,
	}
	done := s.operationDone(pending.prompt.OperationID)

	select {
	case pending.response <- response:
		return true, nil
	case <-done:
		clear(response.PIN)

		return false, nil
	case <-ctx.Done():
		clear(response.PIN)

		return false, ctx.Err()
	}
}

func (s *Service) LookupMDS(ctx context.Context, req MDSLookupRequest) (MDSLookupEnvelope, error) {
	aaguid, err := uuid.Parse(req.AAGUID)
	if err != nil {
		return MDSLookupEnvelope{}, model.NewRuntimeError(model.ErrorInvalidOperation, "invalid AAGUID", err)
	}

	opts := []ctapkit.MDSOption{}
	if req.Source != "" {
		opts = append(opts, ctapkit.WithMDSSource(req.Source))
	}
	if req.CacheDir != "" {
		opts = append(opts, ctapkit.WithMDSCacheDir(req.CacheDir))
	}
	if req.Refresh {
		opts = append(opts, ctapkit.WithMDSRefresh())
	}

	result, err := ctapkit.LookupMDS(ctx, aaguid, opts...)
	if err != nil {
		return MDSLookupEnvelope{}, err
	}

	return MDSLookupEnvelope{Result: result}, nil
}

func (s *Service) session(id SessionID) (*managedSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.sessions[id]

	return session, ok
}

func (s *Service) selectDevice(ctx context.Context, selector string) (ctapkit.Device, error) {
	s.mu.RLock()
	devices := append([]ctapkit.Device(nil), s.devices...)
	s.mu.RUnlock()

	if len(devices) == 0 {
		discovered, err := ctapkit.DiscoverDevices(ctx)
		if err != nil {
			return ctapkit.Device{}, err
		}

		devices = discovered
		s.mu.Lock()
		s.devices = discovered
		s.mu.Unlock()
	}

	return ctapkit.SelectDevice(devices, selector)
}

func (s *Service) registerOperation(operation *operationState) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.operations[operation.id] = operation
}

func (s *Service) unregisterOperation(id OperationID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if operation, ok := s.operations[id]; ok {
		close(operation.done)
	}
	delete(s.operations, id)
}

func (s *Service) operationDone(id OperationID) <-chan struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	operation, ok := s.operations[id]
	if !ok {
		closed := make(chan struct{})
		close(closed)

		return closed
	}

	return operation.done
}

func (s *Service) registerInteraction(prompt InteractionPrompt, response chan model.InteractionResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.interactions[prompt.InteractionID] = &pendingInteraction{
		prompt:   prompt,
		response: response,
	}
}

func (s *Service) unregisterInteraction(id InteractionID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.interactions, id)
}

func (s *Service) emit(name string, payload any) {
	s.mu.RLock()
	emitter := s.emitter
	s.mu.RUnlock()

	if emitter == nil {
		return
	}

	emitter.Emit(name, payload)
}

func (m *managedSession) snapshot() SessionSnapshot {
	m.mu.RLock()
	running := m.activeOperation != ""
	openedAt := m.openedAt
	updatedAt := m.updatedAt
	m.mu.RUnlock()

	return SessionSnapshot{
		ID:        m.id,
		Info:      m.session.Info(),
		Running:   running,
		OpenedAt:  openedAt,
		UpdatedAt: updatedAt,
	}
}

func (m *managedSession) setActiveOperation(id OperationID) {
	m.mu.Lock()
	m.activeOperation = id
	m.updatedAt = time.Now().UTC()
	m.mu.Unlock()
}

func (m *managedSession) touch() {
	m.mu.Lock()
	m.updatedAt = time.Now().UTC()
	m.mu.Unlock()
}

func (m *managedSession) currentOperation() OperationID {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.activeOperation
}

type sessionEventSink struct {
	service   *Service
	sessionID SessionID
}

func (s sessionEventSink) Emit(event model.OperationEvent) {
	if s.service == nil {
		return
	}

	s.service.emitOperationEvent(s.sessionID, event)
}

func (s *Service) emitOperationEvent(sessionID SessionID, event model.OperationEvent) {
	session, ok := s.session(sessionID)
	if !ok {
		return
	}

	s.emit(EventOperationEvent, OperationEventEnvelope{
		OperationID: session.currentOperation(),
		SessionID:   sessionID,
		Event:       event,
	})
}

type interactionHandler struct {
	service     *Service
	sessionID   SessionID
	operationID OperationID
}

func (h interactionHandler) RequestInteraction(req model.InteractionRequest) (model.InteractionResponse, error) {
	if h.service == nil {
		return model.InteractionResponse{}, invalidOperationError("interaction service is required")
	}

	prompt := InteractionPrompt{
		InteractionID: newInteractionID(),
		OperationID:   h.operationID,
		SessionID:     h.sessionID,
		Request:       req,
	}
	response := make(chan model.InteractionResponse)
	h.service.registerInteraction(prompt, response)
	h.service.emit(EventInteractionRequested, prompt)
	defer h.service.unregisterInteraction(prompt.InteractionID)

	select {
	case answer := <-response:
		return answer, nil
	case <-h.service.operationDone(h.operationID):
		return model.InteractionResponse{}, model.NewRuntimeError(model.ErrorCanceled, "interaction canceled", nil)
	}
}

func discoverOptions(req DiscoverRequest) []ctapkit.DiscoverOption {
	if req.Mode == "" || req.Mode == transport.ModeAuto {
		return nil
	}

	return []ctapkit.DiscoverOption{ctapkit.WithTransport(req.Mode)}
}

func runOptions(verificationFlow model.VerificationFlow) []ctapkit.RunOption {
	if verificationFlow == model.VerificationFlowDefault {
		return nil
	}

	return []ctapkit.RunOption{ctapkit.WithVerificationFlow(verificationFlow)}
}

func deviceReports(devices []ctapkit.Device) []report.DeviceReport {
	reports := make([]report.DeviceReport, 0, len(devices))
	for _, device := range devices {
		reports = append(reports, device.Report())
	}

	return reports
}

func newSessionID() SessionID {
	return SessionID(uuid.NewString())
}

func newOperationID() OperationID {
	return OperationID(uuid.NewString())
}

func newInteractionID() InteractionID {
	return InteractionID(uuid.NewString())
}
