package service

import (
	"context"
	"slices"
	"sync"
	"time"

	ghid "github.com/go-ctap/hid"
	ctapkit "github.com/go-ctap/kit"
	kitlog "github.com/go-ctap/kit/internal/logging"
	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/failure"
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
	enrichment        discoveryEnrichment

	devices      []ctapkit.Device
	sessions     map[SessionID]*managedSession
	operations   map[OperationID]*operationState
	interactions map[InteractionID]*pendingInteraction
	logs         *ctapkit.LogJournal
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
	kind      model.OperationKind
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
		enrichment:       newDiscoveryEnrichment(),
		logs:             ctapkit.NewLogJournal(),
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
	enrichmentCancel := s.enrichment.cancel
	enrichmentDone := s.enrichment.done
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

	if enrichmentCancel != nil {
		enrichmentCancel()
	}
	for _, operation := range operations {
		operation.cancel()
	}

	var cleanupErr error
	if receiver != nil {
		if err := receiver.Close(); err != nil {
			cleanupErr = failure.Wrap(
				failure.CodeTransportFailure,
				err,
				failure.WithPhase(failure.PhaseCleanup),
			)
		}
	}
	if monitorDone != nil {
		<-monitorDone
	}
	if enrichmentDone != nil {
		<-enrichmentDone
	}
	for _, session := range sessions {
		if err := session.session.Close(); err != nil && cleanupErr == nil {
			cleanupErr = err
		}
		s.waitForSessionOperations(session.id)
	}

	return cleanupErr
}

func (s *Service) Discover(ctx context.Context, req DiscoverRequest) (DiscoverySnapshot, error) {
	started := time.Now()
	snapshot, err := s.discoverSnapshot(ctx, req)
	s.logs.Append(kitlog.Finish(model.LogEntry{
		Timestamp: started.UTC(),
		Layer:     model.LogLayerService,
		Code:      model.LogCodeDiscoveryRun,
		Request:   kitlog.Payload(kitlog.SafeValue(req)),
		Response:  kitlog.Payload(kitlog.SafeValue(snapshot)),
	}, started, err))

	return snapshot, err
}

func (s *Service) OpenSession(ctx context.Context, req OpenSessionRequest) (snapshot SessionSnapshot, returnErr error) {
	sessionID := newSessionID()
	started := time.Now()
	defer func() {
		s.logs.Append(kitlog.Finish(model.LogEntry{
			Timestamp: started.UTC(),
			Layer:     model.LogLayerSession,
			Code:      model.LogCodeSessionOpen,
			Request:   kitlog.Payload(kitlog.SafeValue(req)),
			Response:  kitlog.Payload(kitlog.SafeValue(snapshot)),
			SessionID: string(sessionID),
		}, started, returnErr))
	}()

	if s.isClosed() {
		return SessionSnapshot{}, closedServiceError(failure.PhaseSession)
	}
	device, err := s.selectDevice(req.Selector)
	if err != nil {
		return SessionSnapshot{}, err
	}
	releaseDevice, err := s.claimDeviceForSession(ctx, device.Report())
	if err != nil {
		return SessionSnapshot{}, err
	}
	defer releaseDevice()
	opts := []ctapkit.OpenSessionOption{
		ctapkit.WithEventSink(sessionEventSink{service: s, sessionID: sessionID}),
		ctapkit.WithLogJournal(s.logs),
	}
	if s.strictPermissions {
		opts = append(opts, ctapkit.WithStrictPermissions())
	}

	openCtx := kitlog.WithCorrelation(ctx, string(sessionID), "", "")
	session, err := ctapkit.OpenSession(openCtx, device, opts...)
	if err != nil {
		return SessionSnapshot{}, err
	}

	now := time.Now().UTC()
	managed := &managedSession{
		id:        sessionID,
		session:   session,
		device:    s.reportWithMetadata(device.Report()),
		openedAt:  now,
		updatedAt: now,
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = session.Close()

		return SessionSnapshot{}, closedServiceError(failure.PhaseSession)
	}
	if !deviceReportPresent(deviceReports(s.devices), managed.device) {
		s.mu.Unlock()
		_ = session.Close()

		return SessionSnapshot{}, invalidSessionError()
	}
	s.sessions[managed.id] = managed
	snapshot = managed.snapshot(false)
	s.mu.Unlock()

	return snapshot, nil
}

func (s *Service) Sessions() []SessionSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	snapshots := make([]SessionSnapshot, 0, len(s.sessions))
	for _, session := range s.sessions {
		snapshots = append(snapshots, session.snapshot(s.sessionOperationLocked(session.id) != nil))
	}

	return snapshots
}

func (s *Service) Session(id SessionID) (SessionSnapshot, error) {
	s.mu.Lock()
	session, ok := s.sessions[id]
	if !ok {
		s.mu.Unlock()
		return SessionSnapshot{}, invalidSessionError()
	}
	snapshot := session.snapshot(s.sessionOperationLocked(id) != nil)
	s.mu.Unlock()

	return snapshot, nil
}

func (s *Service) CloseSession(id SessionID) (snapshot SessionSnapshot, returnErr error) {
	started := time.Now()
	defer func() {
		s.logs.Append(kitlog.Finish(model.LogEntry{
			Timestamp: started.UTC(),
			Layer:     model.LogLayerSession,
			Code:      model.LogCodeSessionClose,
			Request:   kitlog.Payload(kitlog.SafeValue(map[string]any{"sessionId": id})),
			Response:  kitlog.Payload(kitlog.SafeValue(snapshot)),
			SessionID: string(id),
		}, started, returnErr))
	}()

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
	s.startEnrichment()

	snapshot = session.snapshot(false)

	return snapshot, err
}

func (s *Service) CloseAllSessions() (snapshots []SessionSnapshot, returnErr error) {
	started := time.Now()
	defer func() {
		s.logs.Append(kitlog.Finish(model.LogEntry{
			Timestamp: started.UTC(),
			Layer:     model.LogLayerSession,
			Code:      model.LogCodeSessionClose,
			Params:    map[string]string{"scope": "all"},
			Request:   kitlog.Payload(kitlog.SafeValue(map[string]any{"all": true})),
			Response:  kitlog.Payload(kitlog.SafeValue(snapshots)),
		}, started, returnErr))
	}()

	s.mu.Lock()
	sessions := make([]*managedSession, 0, len(s.sessions))
	for id, session := range s.sessions {
		sessions = append(sessions, session)
		delete(s.sessions, id)
	}
	s.mu.Unlock()

	snapshots = make([]SessionSnapshot, 0, len(sessions))
	var closeErr error
	for _, session := range sessions {
		s.cancelSessionOperations(session.id)
		if err := session.session.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
		s.waitForSessionOperations(session.id)
		session.updatedAt = time.Now().UTC()

		snapshot := session.snapshot(false)
		snapshots = append(snapshots, snapshot)
	}
	s.startEnrichment()

	return snapshots, closeErr
}

func (s *Service) runOperation(ctx context.Context, req OperationRequest, operation model.Operation) (envelope operationEnvelope, returnErr error) {
	operationID := newOperationID()
	request := operationRequestLogValue(req, operation)
	started := time.Now()
	var operationErr error
	defer func() {
		response := operationEnvelopeLogValue(envelope)
		s.logs.Append(kitlog.Finish(model.LogEntry{
			Timestamp:      started.UTC(),
			Layer:          model.LogLayerOperation,
			Code:           model.LogCodeOperationRun,
			Request:        kitlog.Payload(request),
			Response:       kitlog.Payload(response),
			RedactedFields: slices.Concat(request.RedactedFields, response.RedactedFields),
			OperationKind:  operation.Kind(),
			SessionID:      string(req.SessionID),
			OperationID:    string(operationID),
		}, started, operationErr))
	}()

	session, ok := s.session(req.SessionID)
	if !ok {
		err := invalidSessionError()
		operationErr = err
		envelope = failedOperationEnvelope(operationID, req, operation, err)

		return envelope, nil
	}

	ctx, cancel := context.WithCancel(ctx)
	state := &operationState{
		id:        operationID,
		sessionID: req.SessionID,
		kind:      operation.Kind(),
		cancel:    cancel,
		done:      make(chan struct{}),
	}

	if !s.registerSessionOperation(session, state) {
		cancel()

		err := invalidSessionError()
		operationErr = err
		envelope = failedOperationEnvelope(operationID, req, operation, err)

		return envelope, nil
	}
	defer cancel()
	defer s.unregisterOperation(operationID)

	opts := runOptions(req.VerificationFlow)
	ctx = kitlog.WithCorrelation(ctx, string(req.SessionID), string(operationID), operation.Kind())
	result, err := session.session.Run(ctx, operation, interactionHandler{
		service:     s,
		sessionID:   req.SessionID,
		operationID: operationID,
		kind:        operation.Kind(),
	}, opts...)
	operationErr = err
	sessionClosed := session.session.Info().Closed
	if sessionClosed {
		s.retireSession(session)
	}

	envelope = operationEnvelope{
		OperationID:   operationID,
		SessionID:     req.SessionID,
		Kind:          operation.Kind(),
		SessionClosed: sessionClosed,
		Result:        result,
		Error:         failure.Snapshot(err),
	}

	return envelope, nil
}

func failedOperationEnvelope(operationID OperationID, req OperationRequest, operation model.Operation, err error) operationEnvelope {
	kind := model.OperationKind("")
	if operation != nil {
		kind = operation.Kind()
	}

	return operationEnvelope{
		OperationID: operationID,
		SessionID:   req.SessionID,
		Kind:        kind,
		Error:       failure.Snapshot(err),
	}
}

func (s *Service) CancelOperation(req CancelOperationRequest) bool {
	return s.cancelOperation(req.OperationID)
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

		return false, normalizeServicePhaseError(ctx.Err(), failure.PhaseInteraction)
	}
}

func (s *Service) LookupMDS(ctx context.Context, req MDSLookupRequest) (envelope MDSLookupEnvelope, returnErr error) {
	started := time.Now()
	defer func() {
		s.logs.Append(kitlog.Finish(model.LogEntry{
			Timestamp: started.UTC(),
			Layer:     model.LogLayerService,
			Code:      model.LogCodeMDSLookup,
			Request:   kitlog.Payload(kitlog.SafeValue(req)),
			Response:  kitlog.Payload(kitlog.SafeValue(envelope)),
		}, started, returnErr))
	}()

	aaguid, err := uuid.Parse(req.AAGUID)
	if err != nil {
		return MDSLookupEnvelope{}, failure.Wrap(
			failure.CodeMDSAAGUIDInvalid,
			err,
			failure.WithPhase(failure.PhaseMetadata),
		)
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

	envelope = MDSLookupEnvelope{Result: result}

	return envelope, nil
}

func (s *Service) session(id SessionID) (*managedSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[id]

	return session, ok
}

func (s *Service) retireSession(session *managedSession) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if current := s.sessions[session.id]; current == session {
		delete(s.sessions, session.id)
	}
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
	info := m.session.Info()
	info.Device = m.device

	return SessionSnapshot{
		ID:        m.id,
		Info:      info,
		Running:   running,
		OpenedAt:  m.openedAt,
		UpdatedAt: m.updatedAt,
	}
}

func (s *Service) sessionOperationLocked(id SessionID) *operationState {
	for _, operation := range s.operations {
		if operation.sessionID == id {
			return operation
		}
	}

	return nil
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
	operation := s.sessionOperationLocked(sessionID)
	s.mu.Unlock()
	if !ok {
		return
	}
	operationID := OperationID("")
	if operation != nil {
		operationID = operation.id
		s.logs.Append(operationEventLogEntry(operation, event))
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
	kind        model.OperationKind
}

func (h interactionHandler) RequestInteraction(req model.InteractionRequest) (answer model.InteractionResponse, returnErr error) {
	if h.service == nil {
		return model.InteractionResponse{}, failure.New(failure.CodeInteractionHandlerRequired,
			failure.WithPhase(failure.PhaseInteraction),
		)
	}

	request := interactionRequestLogValue(req)
	requestStarted := time.Now()
	prompt := InteractionPrompt{
		InteractionID: newInteractionID(),
		OperationID:   h.operationID,
		SessionID:     h.sessionID,
		Request:       req,
	}
	response := make(chan model.InteractionResponse)
	h.service.registerInteraction(prompt, response)
	h.service.emit(EventInteractionRequested, prompt)
	h.service.logs.Append(kitlog.Finish(model.LogEntry{
		Timestamp:      requestStarted.UTC(),
		Layer:          model.LogLayerInteraction,
		Code:           model.LogCodeInteractionRequest,
		Request:        kitlog.Payload(request),
		Response:       kitlog.Payload(kitlog.SafeValue(map[string]any{"interactionId": prompt.InteractionID})),
		RedactedFields: request.RedactedFields,
		OperationKind:  h.kind,
		SessionID:      string(h.sessionID),
		OperationID:    string(h.operationID),
	}, requestStarted, nil))
	defer h.service.unregisterInteraction(prompt.InteractionID)

	resolveStarted := time.Now()
	defer func() {
		var result any
		var resolveRedacted []string
		if returnErr == nil {
			response := map[string]any{"canceled": answer.Canceled}
			if answer.Confirmed {
				response["confirmed"] = kitlog.Redacted
				resolveRedacted = append(resolveRedacted, "response.confirmed")
			}
			if len(answer.PIN) != 0 {
				response["pin"] = kitlog.Redacted
				resolveRedacted = append(resolveRedacted, "response.pin")
			}
			result = response
		}
		h.service.logs.Append(kitlog.Finish(model.LogEntry{
			Timestamp:      resolveStarted.UTC(),
			Layer:          model.LogLayerInteraction,
			Code:           model.LogCodeInteractionResolve,
			Params:         map[string]string{"interactionId": string(prompt.InteractionID)},
			Request:        kitlog.Payload(kitlog.SafeValue(map[string]any{"interactionId": prompt.InteractionID})),
			Response:       kitlog.Payload(kitlog.SafeValue(result)),
			RedactedFields: resolveRedacted,
			OperationKind:  h.kind,
			SessionID:      string(h.sessionID),
			OperationID:    string(h.operationID),
		}, resolveStarted, returnErr))
	}()

	select {
	case answer = <-response:
		return answer, nil
	case <-h.service.operationDone(h.operationID):
		err := failure.New(failure.CodeInteractionCanceled,
			failure.WithPhase(failure.PhaseInteraction),
		)

		return model.InteractionResponse{}, err
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
