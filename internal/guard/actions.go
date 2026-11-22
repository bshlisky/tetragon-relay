package guard

// Action classification. Every name is verified against the pinned source,
// pkg/selectors/kernel.go in cilium/tetragon at tag v1.8.0 (commit
// a5a667837d4b1ecd9018797994bb4e39b98702e1):
//
//   - The full action set (kernel.go:48-64's ActionType* constants and the
//     actionTypeTable at kernel.go:67-81) is exactly: Post, SigKill,
//     Override, GetUrl, DnsLookup, NoPost, Signal, TrackSock, UntrackSock,
//     NotifyEnforcer, CleanupEnforcerNotification, Set, UpdateState.
//   - kernel.go:2339-2349's own HasEnforcementAction function is this
//     project's source for which of those are "enforcement": SigKill,
//     Signal, NotifyEnforcer, Override, Set.
//   - The step 2 prompt's requested observe set names FollowFD, UnfollowFD
//     and CopyFD, none of which exist in the pinned action set: they are
//     ActionTypeFollowFd/UnfollowFd/CopyFd (kernel.go:50,52,54), explicitly
//     commented "deprecated" and absent from actionTypeTable, so no YAML
//     spelling of them resolves to a real action in this Tetragon version.
//     Any policy naming them is rejected by G7 as an unknown action, same
//     as any other unrecognized string.
//   - UpdateState (new in 1.8 for stateful policies) is named by neither
//     the prompt's enforcement list nor its observe list, and is not
//     enforcement per kernel.go's own HasEnforcementAction. This project
//     nonetheless treats it as unknown/rejected (G7) rather than silently
//     classifying it as observe, because "ambiguity: implement the
//     interpretation that rejects more" and because UpdateState mutates
//     a policy's own state object across subsequent evaluations, which
//     this step's guardrails have not analyzed for safety; see
//     docs/reports/step-02b.md's open questions.
var enforcementActions = map[string]bool{
	"Sigkill":        true,
	"Signal":         true,
	"NotifyEnforcer": true,
	"Override":       true,
	"Set":            true,
}

// CopyFD, FollowFD and UnfollowFD are deliberately absent: see the package
// doc comment above. Anything not in this map or enforcementActions is
// unknown and rejected by G7, which already covers them correctly without
// listing them explicitly here.
var observeActions = map[string]bool{
	"Post":                        true,
	"NoPost":                      true,
	"TrackSock":                   true,
	"UntrackSock":                 true,
	"GetUrl":                      true,
	"DnsLookup":                   true,
	"CleanupEnforcerNotification": true,
}

// isEnforcementAction reports whether action is one of this version's
// enforcement actions.
func isEnforcementAction(action string) bool { return enforcementActions[action] }

// isObserveAction reports whether action is one of this version's observe
// actions.
func isObserveAction(action string) bool { return observeActions[action] }

// isKnownAction reports whether action is any recognized action name
// (enforcement or observe) in the pinned Tetragon version.
func isKnownAction(action string) bool {
	return isEnforcementAction(action) || isObserveAction(action)
}
