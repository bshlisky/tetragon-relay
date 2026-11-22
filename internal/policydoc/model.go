package policydoc

// Typed model (step 2 prompt Part B6): Go structs for exactly the fields
// guardrails analyze. Field names/types/json tags are taken from the
// pinned source, pkg/k8s/apis/cilium.io/v1alpha1/types.go and
// tracing_policy_types.go in cilium/tetragon at tag v1.8.0 (commit
// a5a667837d4b1ecd9018797994bb4e39b98702e1); every struct below cites the
// line range it was transcribed from.
//
// Fields guardrails never inspect (loader, options, enforcers,
// selectorsMacros' non-selector shape already modeled separately, state,
// most KProbeArg/ActionSelector metadata like messages, tags, rate limits)
// are decoded as generic map[string]interface{}/[]interface{} values: they
// still get strictjson's duplicate/fold-collision-key and depth checking,
// just not field-name enforcement, and B7's completeness cross-check
// catches any matchActions hidden in a field this model does not look
// inside of.

// rawDoc is the root of the typed model, matching a TracingPolicy's
// top-level shape (tracing_policy_types.go:44-49, 83-159).
type rawDoc struct {
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	Metadata   map[string]interface{} `json:"metadata"`
	Spec       rawSpec                `json:"spec"`
}

type rawSpec struct {
	KProbes     []rawKProbeSpec     `json:"kprobes,omitempty"`
	Tracepoints []rawTracepointSpec `json:"tracepoints,omitempty"`
	Loader      bool                `json:"loader,omitempty"`
	UProbes     []rawUProbeSpec     `json:"uprobes,omitempty"`
	LsmHooks    []rawLsmHookSpec    `json:"lsmhooks,omitempty"`

	// Present in the schema but rejected by B4 before this decode would
	// need to interpret their contents meaningfully; modeled loosely
	// only so an otherwise-schema-valid-but-B4-rejected document still
	// decodes far enough to report the right error.
	Usdts             []map[string]interface{} `json:"usdts,omitempty"`
	Fentries          []map[string]interface{} `json:"fentries,omitempty"`
	PodSelector       map[string]interface{}   `json:"podSelector,omitempty"`
	ContainerSelector map[string]interface{}   `json:"containerSelector,omitempty"`
	HostSelector      map[string]interface{}   `json:"hostSelector,omitempty"`
	NodeSelector      map[string]interface{}   `json:"nodeSelector,omitempty"`

	Lists           []rawListSpec            `json:"lists,omitempty"`
	Enforcers       []map[string]interface{} `json:"enforcers,omitempty"`
	Options         []map[string]interface{} `json:"options,omitempty"`
	SelectorsMacros map[string]rawSelector   `json:"selectorsMacros,omitempty"`
	States          []map[string]interface{} `json:"state,omitempty"`
}

// rawKProbeSpec: types.go:33-73.
type rawKProbeSpec struct {
	Call            string                 `json:"call"`
	Return          bool                   `json:"return,omitempty"`
	Syscall         bool                   `json:"syscall,omitempty"`
	Message         string                 `json:"message,omitempty"`
	Args            []rawKProbeArg         `json:"args,omitempty"`
	Data            []rawKProbeArg         `json:"data,omitempty"`
	ReturnArg       *rawKProbeArg          `json:"returnArg,omitempty"`
	ReturnArgAction string                 `json:"returnArgAction,omitempty"`
	Selectors       []rawSelector          `json:"selectors,omitempty"`
	Tags            []string               `json:"tags,omitempty"`
	Ignore          map[string]interface{} `json:"ignore,omitempty"`
}

// rawTracepointSpec: types.go:483-508.
type rawTracepointSpec struct {
	Subsystem string         `json:"subsystem"`
	Event     string         `json:"event"`
	Message   string         `json:"message,omitempty"`
	Args      []rawKProbeArg `json:"args,omitempty"`
	Selectors []rawSelector  `json:"selectors,omitempty"`
	Tags      []string       `json:"tags,omitempty"`
	Raw       bool           `json:"raw,omitempty"`
}

// rawUProbeSpec: types.go:518-570.
type rawUProbeSpec struct {
	Path          string                 `json:"path"`
	BTFPath       string                 `json:"btfPath,omitempty"`
	Symbols       []string               `json:"symbols,omitempty"`
	Offsets       []uint64               `json:"offsets,omitempty"`
	Addrs         []uint64               `json:"addrs,omitempty"`
	RefCtrOffsets []uint64               `json:"refCtrOffsets,omitempty"`
	Message       string                 `json:"message,omitempty"`
	Selectors     []rawSelector          `json:"selectors,omitempty"`
	Args          []rawKProbeArg         `json:"args,omitempty"`
	Data          []rawKProbeArg         `json:"data,omitempty"`
	Tags          []string               `json:"tags,omitempty"`
	Return        bool                   `json:"return,omitempty"`
	ReturnArg     *rawKProbeArg          `json:"returnArg,omitempty"`
	BinaryDigests []string               `json:"binaryDigests,omitempty"`
	Ignore        map[string]interface{} `json:"ignore,omitempty"`
}

// rawLsmHookSpec: types.go:599-617.
type rawLsmHookSpec struct {
	Hook      string         `json:"hook"`
	Message   string         `json:"message,omitempty"`
	Args      []rawKProbeArg `json:"args,omitempty"`
	Selectors []rawSelector  `json:"selectors,omitempty"`
	Tags      []string       `json:"tags,omitempty"`
}

// rawKProbeArg: types.go:75-129.
type rawKProbeArg struct {
	Index            uint32  `json:"index"`
	Type             string  `json:"type,omitempty"`
	Resolve          string  `json:"resolve,omitempty"`
	SizeArgIndex     uint32  `json:"sizeArgIndex,omitempty"`
	SizeFromArgIndex *uint32 `json:"sizeFromArgIndex,omitempty"`
	ReturnCopy       bool    `json:"returnCopy,omitempty"`
	MaxData          bool    `json:"maxData,omitempty"`
	Label            string  `json:"label,omitempty"`
	Source           string  `json:"source,omitempty"`
	BTFType          string  `json:"btfType,omitempty"`
	BTFTypeModule    string  `json:"btfTypeModule,omitempty"`
}

// rawListSpec: types.go:619-635.
type rawListSpec struct {
	Name      string   `json:"name"`
	Values    []string `json:"values,omitempty"`
	Type      string   `json:"type,omitempty"`
	Pattern   *string  `json:"pattern,omitempty"`
	Validated bool     `json:"validated,omitempty"`
}

// rawSelector models KProbeSelector (types.go:152-219): the fields
// guardrails analyze (MatchPIDs, MatchArgs, MatchActions, MatchReturnArgs,
// MatchReturnActions, MatchBinaries, MatchParentBinaries) are fully typed;
// everything else is decoded loosely so unmodeled content still round-trips
// through strictjson without an unknown-field error, relying on B7's
// completeness cross-check as the safety net for matchActions specifically.
type rawSelector struct {
	Label                  string                   `json:"label,omitempty"`
	MatchPIDs              []rawPIDSelector         `json:"matchPIDs,omitempty"`
	MatchArgs              []rawArgSelector         `json:"matchArgs,omitempty"`
	MatchCmdArgs           []map[string]interface{} `json:"matchCmdArgs,omitempty"`
	MatchData              []rawArgSelector         `json:"matchData,omitempty"`
	MatchActions           []rawActionSelector      `json:"matchActions,omitempty"`
	MatchReturnArgs        []rawArgSelector         `json:"matchReturnArgs,omitempty"`
	MatchReturnActions     []rawActionSelector      `json:"matchReturnActions,omitempty"`
	MatchBinaries          []rawBinarySelector      `json:"matchBinaries,omitempty"`
	MatchParentBinaries    []rawBinarySelector      `json:"matchParentBinaries,omitempty"`
	MatchNamespaces        []map[string]interface{} `json:"matchNamespaces,omitempty"`
	MatchNamespaceChanges  []map[string]interface{} `json:"matchNamespaceChanges,omitempty"`
	MatchCapabilities      []map[string]interface{} `json:"matchCapabilities,omitempty"`
	MatchCapabilityChanges []map[string]interface{} `json:"matchCapabilityChanges,omitempty"`
	// MatchWorkloads (types.go:201-202, 263-278) embeds PodSelector,
	// ContainerSelector and HostSelector: all Kubernetes-only per B4.
	// Modeled so its presence can be rejected explicitly rather than
	// silently ignored.
	MatchWorkloads   map[string]interface{}   `json:"matchWorkloads,omitempty"`
	MatchUserCallers []map[string]interface{} `json:"matchUserCallers,omitempty"`
	MatchStates      []map[string]interface{} `json:"matchStates,omitempty"`
	Macros           []string                 `json:"macros,omitempty"`
	MatchCEL         map[string]interface{}   `json:"matchCEL,omitempty"`
}

// rawPIDSelector: types.go:318-333.
type rawPIDSelector struct {
	Operator       string   `json:"operator"`
	Values         []uint32 `json:"values,omitempty"`
	IsNamespacePID bool     `json:"isNamespacePID,omitempty"`
	FollowForks    bool     `json:"followForks,omitempty"`
}

// rawArgSelector: types.go:335-351 (also used for MatchData/MatchReturnArgs,
// which share ArgSelector's shape upstream).
type rawArgSelector struct {
	Index    uint32   `json:"index,omitempty"`
	Args     []uint32 `json:"args,omitempty"`
	Operator string   `json:"operator"`
	Values   []string `json:"values,omitempty"`
}

// rawBinarySelector: types.go:140-150.
type rawBinarySelector struct {
	Operator       string   `json:"operator"`
	Values         []string `json:"values"`
	FollowChildren bool     `json:"followChildren,omitempty"`
}

// rawActionSelector: types.go:366-481. Every field the CRD allows is
// modeled (not just the ones guard logic reads) so strictjson's exact
// field-name enforcement does not reject an otherwise schema-valid
// document.
type rawActionSelector struct {
	Action           string   `json:"action"`
	ArgURL           string   `json:"argUrl,omitempty"`
	ArgFqdn          string   `json:"argFqdn,omitempty"`
	ArgError         int32    `json:"argError,omitempty"`
	ArgSig           uint32   `json:"argSig,omitempty"`
	ArgSock          uint32   `json:"argSock,omitempty"`
	ArgIndex         uint32   `json:"argIndex,omitempty"`
	ArgValue         uint64   `json:"argValue,omitempty"`
	ArgRegs          []string `json:"argRegs,omitempty"`
	ArgNewSymbol     string   `json:"argNewSymbol,omitempty"`
	ArgNewAddr       uint64   `json:"argNewAddr,omitempty"`
	ArgNewOffset     int64    `json:"argNewOffset,omitempty"`
	SoPath           string   `json:"sopath,omitempty"`
	RateLimit        string   `json:"rateLimit,omitempty"`
	RateLimitScope   string   `json:"rateLimitScope,omitempty"`
	KernelStackTrace bool     `json:"kernelStackTrace,omitempty"`
	UserStackTrace   bool     `json:"userStackTrace,omitempty"`
	ImaHash          bool     `json:"imaHash,omitempty"`
	// State: types.go:467-469, 367-377. Only valid with the UpdateState
	// action; modeled loosely since guardrails treat UpdateState as
	// unknown/reject (see internal/guard's action classification and
	// docs/reports/step-02b.md's open questions).
	State map[string]interface{} `json:"state,omitempty"`
}
