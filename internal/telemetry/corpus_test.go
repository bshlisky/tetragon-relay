package telemetry

import (
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

// The benchmark corpus: a deterministic, varied mix of the events a busy
// RHEL server sends (55 % exec, 40 % exit, 5 % kprobe), shaped like
// Tetragon v1.8.0's default output: exec_id is base64("node:ktime:pid"),
// pids and timestamps vary per event, arguments come from templates with
// varying ids, hosts and paths, and a few carry secrets or ~/.ssh paths
// so redaction does real work. Identical repeated events would compress
// unrealistically well (step 7b Z4) and hit no redaction branches.

const corpusNode = "host-0001.prod.example.internal"

var (
	corpusBinaries = []string{
		"/usr/bin/bash", "/usr/bin/curl", "/usr/bin/python3.9", "/usr/sbin/sshd", "/usr/bin/systemctl",
		"/usr/bin/ls", "/usr/bin/grep", "/usr/bin/awk", "/usr/bin/sed", "/usr/bin/cat", "/usr/bin/git",
		"/usr/lib/jvm/java-17-openjdk/bin/java", "/opt/app/bin/worker", "/usr/bin/rpm", "/usr/bin/dnf",
		"/usr/sbin/crond", "/usr/bin/sleep", "/usr/bin/ps", "/usr/bin/ssh", "/usr/libexec/platform-python",
	}
	corpusCwds = []string{"/", "/root", "/var/lib/app", "/opt/app", "/home/alice", "/home/bob/src/service", "/tmp", "/var/log"}
	corpusArgs = []string{
		"-s -o /dev/null -w %%{http_code} https://api.internal.example/v1/items?id=%d",
		"-c /opt/app/bin/poll.sh --interval %d --target db-%d.prod.example.internal",
		"status tetragon.service --no-pager",
		"-la /var/log/app/%d",
		"-E 'ERROR|WARN' /var/log/app/service-%d.log",
		"-F: '{print $%d}' /etc/passwd",
		"-i s/version=.*/version=%d/ /opt/app/conf/app.properties",
		"fetch --prune origin refs/heads/release-%d",
		"-Xmx%dm -jar /opt/app/lib/service.jar --spring.profiles.active=prod",
		"--login --password hunter%d --host db-%d.internal",
		"-q --whatprovides /usr/lib64/libssl.so.%d",
		"-i /home/alice/.ssh/id_ed25519 deploy@build-%d.example.internal",
		"%d",
		"-eo pid,ppid,cmd --sort=-%%cpu",
		"curl -H 'Authorization: Bearer token=%08x' https://vault.internal/v1/secret",
	}
	corpusKprobeFiles = []string{"/etc/shadow", "/etc/passwd", "/etc/tetragon/tetragon.yaml", "/home/alice/.ssh/authorized_keys", "/var/lib/app/data/%d.db"}
)

func corpusProcess(r *rand.Rand, ts time.Time) *tetragonpb.Process {
	pid := uint32(1000 + r.IntN(4_000_000)) //nolint:gosec // G115: bounded
	ktime := uint64(ts.UnixNano()) - uint64(r.IntN(1_000_000_000))
	execID := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%d:%d", corpusNode, ktime, pid)))
	parentID := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%d:%d", corpusNode, ktime-uint64(r.IntN(1e9)), pid-uint32(1+r.IntN(900)))))
	uid := uint32(0)
	if r.IntN(3) == 0 {
		uid = uint32(1000 + r.IntN(10)) //nolint:gosec // G115: bounded
	}
	args := corpusArgs[r.IntN(len(corpusArgs))]
	return &tetragonpb.Process{
		ExecId: execID, Pid: wrapperspb.UInt32(pid), Uid: wrapperspb.UInt32(uid), Auid: wrapperspb.UInt32(uid), Tid: wrapperspb.UInt32(pid),
		Cwd: corpusCwds[r.IntN(len(corpusCwds))], Binary: corpusBinaries[r.IntN(len(corpusBinaries))],
		Arguments: fmt.Sprintf(args, r.IntN(100000), r.IntN(100)), Flags: "execve clone",
		StartTime: timestamppb.New(ts.Add(-time.Duration(r.IntN(1e9)))), ParentExecId: parentID, Refcnt: uint32(r.IntN(3)), //nolint:gosec // G115: bounded
		InInitTree: wrapperspb.Bool(false),
		EnvironmentVariables: []*tetragonpb.EnvVar{
			{Key: "PATH", Value: "/usr/local/bin:/usr/bin:/bin"}, {Key: "HOME", Value: "/root"},
			{Key: "SECRET_TOKEN", Value: fmt.Sprintf("%016x", r.Uint64())},
		},
	}
}

// corpusEvent is event i of the corpus.
func corpusEvent(r *rand.Rand, i int) *tetragonpb.GetEventsResponse {
	ts := time.Unix(1795694400, 0).Add(time.Duration(i) * 200 * time.Microsecond)
	ev := &tetragonpb.GetEventsResponse{Time: timestamppb.New(ts), NodeName: corpusNode}
	proc, parent := corpusProcess(r, ts), corpusProcess(r, ts)
	var anc []*tetragonpb.Process
	for range 1 + r.IntN(3) {
		anc = append(anc, corpusProcess(r, ts))
	}
	switch k := r.IntN(100); {
	case k < 55:
		ev.Event = &tetragonpb.GetEventsResponse_ProcessExec{ProcessExec: &tetragonpb.ProcessExec{Process: proc, Parent: parent, Ancestors: anc}}
	case k < 95:
		ev.Event = &tetragonpb.GetEventsResponse_ProcessExit{ProcessExit: &tetragonpb.ProcessExit{
			Process: proc, Parent: parent, Status: uint32(r.IntN(3)), Time: timestamppb.New(ts), //nolint:gosec // G115: bounded
		}}
	default:
		path := corpusKprobeFiles[r.IntN(len(corpusKprobeFiles))]
		if path[len(path)-1] == 'b' {
			path = fmt.Sprintf(path, r.IntN(1000))
		}
		ev.Event = &tetragonpb.GetEventsResponse_ProcessKprobe{ProcessKprobe: &tetragonpb.ProcessKprobe{
			Process: proc, Parent: parent, FunctionName: "security_file_permission", PolicyName: "file-monitoring",
			Action: tetragonpb.KprobeAction_KPROBE_ACTION_POST,
			Args: []*tetragonpb.KprobeArgument{
				{Arg: &tetragonpb.KprobeArgument_FileArg{FileArg: &tetragonpb.KprobeFile{Path: path, Permission: "-rw-r-----"}}},
				{Arg: &tetragonpb.KprobeArgument_IntArg{IntArg: 4}},
			},
			Ancestors: anc,
		}}
	}
	return ev
}

// benchCorpus returns n distinct corpus events, already marshaled the way
// Tetragon sends them, so the measured pipeline does the decoding.
func benchCorpus(n int) [][]byte {
	r := rand.New(rand.NewPCG(7, 2026)) //nolint:gosec // G404: deterministic test corpus
	out := make([][]byte, n)
	for i := range out {
		b, err := proto.Marshal(corpusEvent(r, i))
		if err != nil {
			panic(err)
		}
		out[i] = b
	}
	return out
}
