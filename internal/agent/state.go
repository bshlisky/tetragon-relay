package agent

import "fmt"

// State is one of architecture doc 8.3/8.4's ten relay-agent states.
type State int

// The ten states architecture doc 8.4's state diagram defines.
const (
	StateUnenrolled State = iota
	StateEnrolling
	StateConnecting
	StateSyncing
	StateSteady
	StateApplying
	StateRollback
	StateDrift
	StateDegraded
	StateRevoked
)

// String implements fmt.Stringer, matching architecture doc 8.4's state
// names exactly (used in audit records and Terminate/Alert details).
func (s State) String() string {
	switch s {
	case StateUnenrolled:
		return "UNENROLLED"
	case StateEnrolling:
		return "ENROLLING"
	case StateConnecting:
		return "CONNECTING"
	case StateSyncing:
		return "SYNCING"
	case StateSteady:
		return "STEADY"
	case StateApplying:
		return "APPLYING"
	case StateRollback:
		return "ROLLBACK"
	case StateDrift:
		return "DRIFT"
	case StateDegraded:
		return "DEGRADED"
	case StateRevoked:
		return "REVOKED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(s))
	}
}

// Event is one state-machine input, named after the transition labels in
// architecture doc 8.4's state diagram.
type Event int

// The transition-triggering events architecture doc 8.4's diagram labels.
const (
	// EventJoinTokenValid: UNENROLLED -> ENROLLING ("join token / TPM attestation").
	EventJoinTokenValid Event = iota
	// EventSVIDIssued: ENROLLING -> CONNECTING.
	EventSVIDIssued
	// EventEnrollFailed: ENROLLING -> UNENROLLED ("failure (backoff)").
	EventEnrollFailed
	// EventHelloAck: CONNECTING -> SYNCING.
	EventHelloAck
	// EventConnectTimeout: CONNECTING -> DEGRADED ("5 min without success").
	EventConnectTimeout
	// EventConditionsClear: DEGRADED -> CONNECTING.
	EventConditionsClear
	// EventInSync: SYNCING -> STEADY.
	EventInSync
	// EventBundleReceived: SYNCING -> APPLYING.
	EventBundleReceived
	// EventVerifiedBundle: STEADY -> APPLYING.
	EventVerifiedBundle
	// EventHealthPass: APPLYING -> STEADY.
	EventHealthPass
	// EventHealthFail: APPLYING -> ROLLBACK.
	EventHealthFail
	// EventLKGReasserted: ROLLBACK -> STEADY.
	EventLKGReasserted
	// EventDigestMismatch: STEADY -> DRIFT.
	EventDigestMismatch
	// EventReassertHolds: DRIFT -> STEADY.
	EventReassertHolds
	// EventReassertFails is DRIFT's self-loop ("stays DRIFT and alerts
	// each cycle otherwise").
	EventReassertFails
	// EventStreamLost: STEADY -> CONNECTING.
	EventStreamLost
	// EventTerminateRevoked: any state -> REVOKED ("entered from any
	// state on Terminate(REVOKED)").
	EventTerminateRevoked
	// EventOperatorReenroll: REVOKED -> UNENROLLED.
	EventOperatorReenroll
	// EventDegradedCondition: architecture doc 8.4's DEGRADED row lists
	// three independent entry conditions ("No controller for > 5 min,
	// or cert < 15 min, or trust metadata expired"), but the state
	// diagram itself only draws one edge, CONNECTING -> DEGRADED
	// (EventConnectTimeout). docs/prompts/step-06a.md D2 explicitly
	// requires "Expiring certificate (under 15 minutes left) puts the
	// agent in DEGRADED" as a control-loop rule, which can fire while
	// already connected (SYNCING/STEADY/APPLYING/ROLLBACK/DRIFT), not
	// only while CONNECTING. This event extends the diagram with the
	// minimum additional edges needed to satisfy that explicit
	// requirement without inventing a different exit than the
	// diagram's own DEGRADED -> CONNECTING; see docs/reports/step-06a.md
	// for this deviation and the open question it is recorded against.
	EventDegradedCondition
)

func (e Event) String() string {
	names := map[Event]string{
		EventJoinTokenValid:    "join_token_valid",
		EventSVIDIssued:        "svid_issued",
		EventEnrollFailed:      "enroll_failed",
		EventHelloAck:          "hello_ack",
		EventConnectTimeout:    "connect_timeout",
		EventConditionsClear:   "conditions_clear",
		EventInSync:            "in_sync",
		EventBundleReceived:    "bundle_received",
		EventVerifiedBundle:    "verified_bundle",
		EventHealthPass:        "health_pass",
		EventHealthFail:        "health_fail",
		EventLKGReasserted:     "lkg_reasserted",
		EventDigestMismatch:    "digest_mismatch",
		EventReassertHolds:     "reassert_holds",
		EventReassertFails:     "reassert_fails",
		EventStreamLost:        "stream_lost",
		EventTerminateRevoked:  "terminate_revoked",
		EventOperatorReenroll:  "operator_reenroll",
		EventDegradedCondition: "degraded_condition",
	}
	if n, ok := names[e]; ok {
		return n
	}
	return fmt.Sprintf("UNKNOWN(%d)", int(e))
}

// transitions is architecture doc 8.4's state diagram, transcribed
// edge-for-edge (docs/prompts/step-06a.md D1: "Implement the states and
// transitions of architecture 8.3 as an explicit, table-driven state
// machine"). EventTerminateRevoked is handled separately in Fire (it is
// valid from every state, which would otherwise require repeating the
// same entry ten times here).
var transitions = map[State]map[Event]State{
	StateUnenrolled: {
		EventJoinTokenValid: StateEnrolling,
	},
	StateEnrolling: {
		EventSVIDIssued:   StateConnecting,
		EventEnrollFailed: StateUnenrolled,
	},
	StateConnecting: {
		EventHelloAck:       StateSyncing,
		EventConnectTimeout: StateDegraded,
	},
	StateSyncing: {
		EventInSync:            StateSteady,
		EventBundleReceived:    StateApplying,
		EventDegradedCondition: StateDegraded,
	},
	StateSteady: {
		EventVerifiedBundle:    StateApplying,
		EventDigestMismatch:    StateDrift,
		EventStreamLost:        StateConnecting,
		EventDegradedCondition: StateDegraded,
	},
	StateApplying: {
		EventHealthPass:        StateSteady,
		EventHealthFail:        StateRollback,
		EventDegradedCondition: StateDegraded,
	},
	StateRollback: {
		EventLKGReasserted:     StateSteady,
		EventDegradedCondition: StateDegraded,
	},
	StateDrift: {
		EventReassertHolds:     StateSteady,
		EventReassertFails:     StateDrift, // "stays DRIFT and alerts each cycle"
		EventDegradedCondition: StateDegraded,
	},
	StateDegraded: {
		EventConditionsClear: StateConnecting,
	},
	StateRevoked: {
		EventOperatorReenroll: StateUnenrolled,
	},
}

// ErrInvalidTransition is returned by (*StateMachine).Fire when event is
// not a valid transition from the machine's current state.
type ErrInvalidTransition struct {
	From  State
	Event Event
}

func (e *ErrInvalidTransition) Error() string {
	return fmt.Sprintf("agent: invalid transition: event %s is not valid from state %s", e.Event, e.From)
}

// StateMachine implements architecture doc 8.3/8.4: a table-driven state
// machine where every transition is logged as an audit record (D1), and
// no transition ever calls anything that would unload a Tetragon policy
// (structural: this package's control loop only ever calls
// apply.Engine's Apply/Reconcile, both add-before-remove; nothing in this
// file has a handle to, or calls, any "unload everything" primitive).
type StateMachine struct {
	current State
	auditor Auditor
}

// NewStateMachine constructs a StateMachine starting in StateUnenrolled
// (architecture doc 8.4: "[*] --> UNENROLLED"), the state every fresh
// boot (or a REVOKED host after operator re-enrollment) starts from.
// auditor must not be nil (this package's fail-closed convention for
// required collaborators).
func NewStateMachine(auditor Auditor) (*StateMachine, error) {
	if auditor == nil {
		return nil, fmt.Errorf("agent: NewStateMachine: auditor must not be nil")
	}
	return &StateMachine{current: StateUnenrolled, auditor: auditor}, nil
}

// Current returns the machine's current state.
func (m *StateMachine) Current() State { return m.current }

// Fire applies event to the machine. EventTerminateRevoked is valid from
// any state (architecture doc 8.4: "entered from any state on
// Terminate(REVOKED)"); every other event must be a valid edge from the
// current state in transitions, else ErrInvalidTransition (the state is
// left unchanged) and no audit record is written for the rejected event.
func (m *StateMachine) Fire(event Event) error {
	if event == EventTerminateRevoked {
		from := m.current
		m.current = StateRevoked
		m.auditor.Record(AuditEvent{Step: "state_transition", Detail: fmt.Sprintf("%s -> %s (%s)", from, m.current, event)})
		return nil
	}
	next, ok := transitions[m.current][event]
	if !ok {
		return &ErrInvalidTransition{From: m.current, Event: event}
	}
	from := m.current
	m.current = next
	m.auditor.Record(AuditEvent{Step: "state_transition", Detail: fmt.Sprintf("%s -> %s (%s)", from, m.current, event)})
	return nil
}
