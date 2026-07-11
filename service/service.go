package service

import (
	"context"
	"errors"
	"sync"
	"time"

	ghid "github.com/go-ctap/hid"
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
	mu                sync.Mutex
	emitter           EventEmitter
	strictPermissions bool
	closed            bool
	lastDiscoverMode  transport.Mode
	monitor           ghid.EventReceiver
	monitorDone       chan struct{}
	scanDevices       func(context.Context, ...ctapkit.DiscoverOption) ([]ctapkit.Device, error)
	openMonitor       func() (ghid.EventReceiver, error)

	devices      []ctapkit.Device
	sessions     map[SessionID]*managedSession
	operations   map[OperationID]*operationState
	interactions map[InteractionID]*pendingInteraction
}

type managedSession struct {
	id        SessionID
	session   sessionRuntime
	device    report.DeviceReport
	openedAt  time.Time
	updatedAt time.Time
}

type sessionRuntime interface {
	Run(context.Context, model.Operation, model.InteractionHandler, ...ctapkit.RunOption) (model.OperationResult, error)
	Close() error
	Info() model.SessionInfo
}

type operationState struct {
	id        OperationID
	sessionID SessionID
	cancel    context.CancelFunc
	done      chan struct{}
}

type pendingInteraction struct {
	prompt   InteractionPrompt
	response chan model.InteractionResponse
}

func New(opts ...Option) *Service {
	service := &Service{
		sessions:         make(map[SessionID]*managedSession),
		operations:       make(map[OperationID]*operationState),
		interactions:     make(map[InteractionID]*pendingInteraction),
		lastDiscoverMode: transport.ModeAuto,
		scanDevices:      ctapkit.DiscoverDevices,
		openMonitor:      ghid.Events,
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
	if s.closed {
		s.mu.Unlock()

		return nil
	}
	s.closed = true
	receiver := s.monitor
	monitorDone := s.monitorDone
	s.monitor = nil
	s.monitorDone = nil

	sessions := make([]*managedSession, 0, len(s.sessions))
	for id, session := range s.sessions {
		sessions = append(sessions, session)
		delete(s.sessions, id)
	}
	operations := make([]*operationState, 0, len(s.operations))
	for _, operation := range s.operations {
		operations = append(operations, operation)
	}
	s.mu.Unlock()

	var monitorErr error
	if receiver != nil {
		monitorErr = receiver.Close()
	}
	if monitorDone != nil {
		<-monitorDone
	}
	for _, operation := range operations {
		operation.cancel()
	}

	var sessionErr error
	for _, session := range sessions {
		if err := session.session.Close(); err != nil {
			sessionErr = errors.Join(sessionErr, err)
		}
		s.waitForSessionOperations(session.id)
	}

	return errors.Join(monitorErr, sessionErr)
}

func (s *Service) Discover(ctx context.Context, req DiscoverRequest) (DiscoverySnapshot, error) {
	return s.discoverSnapshot(ctx, req)
}

func (s *Service) OpenSession(ctx context.Context, req OpenSessionRequest) (SessionSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return SessionSnapshot{}, err
	}

	if s.isClosed() {
		return SessionSnapshot{}, closedServiceError()
	}

	device, err := s.selectDevice(req.Selector)
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
		device:    device.Report(),
		openedAt:  now,
		updatedAt: now,
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = session.Close()

		return SessionSnapshot{}, closedServiceError()
	}
	if !deviceReportPresent(deviceReports(s.devices), managed.device) {
		s.mu.Unlock()
		_ = session.Close()

		return SessionSnapshot{}, invalidSessionError()
	}
	s.sessions[managed.id] = managed
	snapshot := managed.snapshot(false)
	s.mu.Unlock()

	return snapshot, nil
}

func (s *Service) Sessions(ctx context.Context) ([]SessionSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	snapshots := make([]SessionSnapshot, 0, len(s.sessions))
	for _, session := range s.sessions {
		snapshots = append(snapshots, session.snapshot(s.sessionOperationLocked(session.id) != ""))
	}

	return snapshots, nil
}

func (s *Service) Session(ctx context.Context, id SessionID) (SessionSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return SessionSnapshot{}, err
	}

	s.mu.Lock()
	session, ok := s.sessions[id]
	if !ok {
		s.mu.Unlock()
		return SessionSnapshot{}, invalidSessionError()
	}
	snapshot := session.snapshot(s.sessionOperationLocked(id) != "")
	s.mu.Unlock()

	return snapshot, nil
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

	s.cancelSessionOperations(session.id)
	err := session.session.Close()
	s.waitForSessionOperations(session.id)
	session.updatedAt = time.Now().UTC()

	return session.snapshot(false), err
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
		s.cancelSessionOperations(session.id)
		if err := session.session.Close(); err != nil {
			closeErr = errors.Join(closeErr, err)
		}
		s.waitForSessionOperations(session.id)
		session.updatedAt = time.Now().UTC()

		snapshot := session.snapshot(false)
		snapshots = append(snapshots, snapshot)
	}

	return snapshots, closeErr
}

func (s *Service) runOperation(ctx context.Context, req OperationRequest, operation model.Operation) (operationEnvelope, error) {
	session, ok := s.session(req.SessionID)
	if !ok {
		return operationEnvelope{}, invalidSessionError()
	}

	if operation == nil {
		return operationEnvelope{}, invalidOperationError("operation is required")
	}

	operationID := newOperationID()
	ctx, cancel := context.WithCancel(ctx)
	state := &operationState{
		id:        operationID,
		sessionID: req.SessionID,
		cancel:    cancel,
		done:      make(chan struct{}),
	}

	if !s.registerSessionOperation(session, state) {
		cancel()

		return operationEnvelope{}, invalidSessionError()
	}
	defer cancel()
	defer s.unregisterOperation(operationID)

	opts := runOptions(req.VerificationFlow)
	result, err := session.session.Run(ctx, operation, interactionHandler{
		service:     s,
		sessionID:   req.SessionID,
		operationID: operationID,
	}, opts...)

	envelope := operationEnvelope{
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

	return s.cancelOperation(req.OperationID), nil
}

func (s *Service) cancelOperation(id OperationID) bool {
	s.mu.Lock()
	operation, ok := s.operations[id]
	s.mu.Unlock()

	if !ok {
		return false
	}

	operation.cancel()

	return true
}

func (s *Service) cancelSessionOperations(id SessionID) bool {
	s.mu.Lock()
	operations := make([]*operationState, 0, 1)
	for _, operation := range s.operations {
		if operation.sessionID == id {
			operations = append(operations, operation)
		}
	}
	s.mu.Unlock()

	for _, operation := range operations {
		operation.cancel()
	}

	return len(operations) > 0
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
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[id]

	return session, ok
}

func (s *Service) selectDevice(selector string) (ctapkit.Device, error) {
	s.mu.Lock()
	devices := append([]ctapkit.Device(nil), s.devices...)
	s.mu.Unlock()

	return ctapkit.SelectDevice(devices, selector)
}

func (s *Service) registerSessionOperation(session *managedSession, operation *operationState) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, ok := s.sessions[operation.sessionID]
	if s.closed {
		return false
	}
	if !ok || current != session {
		return false
	}
	s.operations[operation.id] = operation
	session.updatedAt = time.Now().UTC()

	return true
}

func (s *Service) unregisterOperation(id OperationID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if operation, ok := s.operations[id]; ok {
		close(operation.done)
		if session := s.sessions[operation.sessionID]; session != nil {
			session.updatedAt = time.Now().UTC()
		}
	}
	delete(s.operations, id)
}

func (s *Service) operationDone(id OperationID) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()

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
	s.mu.Lock()
	emitter := s.emitter
	closed := s.closed
	s.mu.Unlock()

	if emitter == nil || closed {
		return
	}

	emitter.Emit(name, payload)
}

func (m *managedSession) snapshot(running bool) SessionSnapshot {
	return SessionSnapshot{
		ID:        m.id,
		Info:      m.session.Info(),
		Running:   running,
		OpenedAt:  m.openedAt,
		UpdatedAt: m.updatedAt,
	}
}

func (s *Service) sessionOperationLocked(id SessionID) OperationID {
	for _, operation := range s.operations {
		if operation.sessionID == id {
			return operation.id
		}
	}

	return ""
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
	s.mu.Lock()
	_, ok := s.sessions[sessionID]
	operationID := s.sessionOperationLocked(sessionID)
	s.mu.Unlock()
	if !ok {
		return
	}

	s.emit(EventOperationEvent, OperationEventEnvelope{
		OperationID: operationID,
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
