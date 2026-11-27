# Step 6b report

Work in progress; the full report (sections 1–13) is written when this step's work is
complete. The progress log below records every push.

## Progress log

One dated line per push: commit, what changed, the CI result observed.

- 2026-11-27 `da095c6` (with `83512c5` prompt/review, `29def2e` A1, `efb3bd0` atomic commit, `8217553`/`ee93f6b`/`016af02`/`f89ffbd`/`cf6649d` Part B): run 45935962231: ci ✓, integration ✓, e3 ✓. S1–S6 PASS with the apply worker, outbox and real reachability wired in (no S7+ yet).
- 2026-11-27 `77e5222` (with Part C `81e0351`/`418837c`/`fa63f86`/`33ac160`, Part D/E `17e94d7`/`10e8575`/`5185493`/`484af7d`/`8dc9fe7`/`074dbc7`/`c187ecc`, E3 tooling `929efcd`/`f67f6d4`/`5d29c3e`/`08f45bf`, `be3c97e`, runner `/var/run` fix): run 45938072565: ci ✗ at the gofmt check (`cmd/bundlesign-test/e3bundle.go`: a comment inserted into a struct literal broke field alignment); integration and e3 skipped. Fixed in the next commit.
- 2026-11-27 `8df6333` (with `2ac751b` gofmt): run 45938361280: ci ✓, integration ✓, e3 ✗. S1–S6, S8, S4 PASS. S7 FAIL: relayd verified the monitor bundle, entered APPLYING, logged `apply_plan` and loaded `e3-canary-v1-670120fc`, then systemd logged `Main process exited, code=dumped, status=31/SYS`. `apply.PersistDir`'s `fchown` was killed by the unit's `SystemCallFilter=~@privileged` (`@chown`). S9–S12 failed for the same reason (12 SIGSYS exits in the job; S9 got `REJECTED_GUARDRAIL: G5` because the monitor epoch was never committed). S8 PASS shows `REJECTED_SIGNATURE` over the stream. Fixed in the next commit by removing the chown, not by widening the filter.
