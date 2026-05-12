# Runtime Safety Policy

This file defines the safety contract for any `runtime-safe` family mode.

## Purpose

Runtime work exists to sharpen exploitability and reachability, not to perform invasive testing.

## Runtime Approval

Runtime-safe mode is not enabled by default.

The operator must explicitly approve:

- target environment
- account or credential posture
- allowed request classes
- whether networked commands are permitted

After that approval, the checks below are allowed only within the approved
environment and posture.

## Allowed After Runtime Approval

- passive HTTP requests
- unauthenticated reachability checks
- benign malformed requests
- safe negative tests with fake or clearly invalid identifiers
- controlled-account checks in isolated or explicitly approved environments

## Forbidden by Default

- production writes
- any request likely to mutate production or shared state
- replaying real payment or webhook events
- account takeover of real users
- inventory, business-object, account, payment, file, or credential mutations
- destructive file operations
- repeated high-rate probing
- validating credentials against external services
- including bearer tokens, cookies, API keys, session material, or secret values in reports

## Safe Negative Testing

Safe negative testing must prefer:

- fake identifiers
- invalid signatures
- impossible route parameters
- requests designed to test whether an auth barrier exists before business logic runs

If there is any meaningful chance that a request could mutate state, it is not safe by default.

Runtime-safe requests must be low rate and stop immediately on unexpected
success, unexpected side effect, throttling, lockout, or unexplained state
change.

## Runtime Result Labels

- `confirmed-at-runtime`
- `not-reproduced`
- `blocked-by-ingress-or-environment`
- `unsafe-to-validate-without-separate-approval`

## Operator Expectations

- record exact request posture used
- state environment and account context
- redact request and response bodies before reporting
- stop immediately on unexpected success or unexpected side effect
- update the structured finding inventory rather than creating parallel runtime-only findings
