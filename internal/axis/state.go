package axis

import "fmt"

type State string

const (
	Received          State = "RECEIVED"
	Denied            State = "DENIED"
	Authorized        State = "AUTHORIZED"
	Armed             State = "ARMED"
	Running           State = "RUNNING"
	Exited            State = "EXITED"
	TimedOut          State = "TIMED_OUT"
	Signaled          State = "SIGNALED"
	LaunchFailed      State = "LAUNCH_FAILED"
	Orphaned          State = "ORPHANED"
	AbortedNotStarted State = "ABORTED_NOT_STARTED"
	ResultReleased    State = "RESULT_RELEASED"
	ResultWithheld    State = "RESULT_WITHHELD"
)

var transitions = map[State]map[State]bool{Received: {Denied: true, Authorized: true, AbortedNotStarted: true}, Authorized: {Armed: true, Denied: true, AbortedNotStarted: true}, Armed: {Running: true, AbortedNotStarted: true}, Running: {Exited: true, TimedOut: true, Signaled: true, LaunchFailed: true, Orphaned: true}, Exited: {ResultReleased: true, ResultWithheld: true}, TimedOut: {ResultReleased: true, ResultWithheld: true}, Signaled: {ResultReleased: true, ResultWithheld: true}, LaunchFailed: {ResultWithheld: true}, Orphaned: {ResultWithheld: true}}

func ValidTransition(a, b State) error {
	if !transitions[a][b] {
		return fmt.Errorf("invalid execution transition %s -> %s", a, b)
	}
	return nil
}
