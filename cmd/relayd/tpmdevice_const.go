package main

// productionTPMDevice is the only path a production relayd build (no
// test build tags) ever opens (docs/prompts/step-06a.md C3: "production
// builds accept only /dev/tpmrm0"), and --tpm-device's default under
// every build (including testtpm, where it can be overridden to reach a
// software TPM).
const productionTPMDevice = "/dev/tpmrm0"
