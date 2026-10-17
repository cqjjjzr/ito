HTTP API of the Ito controller.

All request and response bodies use JSON. Request bodies are limited to 64 KiB, and unknown fields are ignored.

## Authentication

### Browser sessions

Browsers initiate sign-in via `GET /api/v1/auth/login`, which redirects to the configured OpenID Connect provider. After authentication, the provider redirects back to `GET /api/v1/auth/callback`. The callback sets the session cookie (`__Host-ito_session`, or `ito_session` when `cookie_secure` is `false`) and redirects to `/`.

The callback also sets the session's CSRF token in the readable cookie `__Host-ito_csrf` (`ito_csrf` when `cookie_secure` is `false`). The same token is returned by `GET /api/v1/session`. Every state-changing request (any method other than `GET` and `HEAD`) must include:

- `X-CSRF-Token`: the session's CSRF token
- `Origin`: the controller's configured `public_url`

An HTTP `401` response indicates that the session has expired or exceeded `session_idle`. Operations marked with the `admin` role require a session whose OIDC ID token included at least one group listed in `oidc.admin_groups` at sign-in.

### Device agents

Device agents authenticate with `Authorization: Bearer itoa_<secret>` using the bearer token returned when the device was claimed. The controller returns `401` if the agent credential has been revoked or replaced, if the device is blocked or deleting, or if the owning account is inactive.

## Concurrency control and revisions

Stateful resources include a numeric `revision` field and return it in the `ETag` header (for example, `"4"`). Update requests must send that ETag back in the `If-Match` header:

- Missing `If-Match` returns `428 Precondition Required`.
- Stale `If-Match` returns `412 Precondition Failed`.

Administrative and revocation endpoints (`POST /devices/{id}/block`, `POST /devices/{id}/unblock`, `POST /devices/{id}/revoke`, and `DELETE /devices/{id}`) accept `If-Match` optionally so concurrent updates from an agent cannot delay revocation or deletion.

When a device update commits, the background reconciler applies the desired state to the Linux kernel:

- `applied_revision` matches `revision` once the reconciler has applied and verified that revision in the kernel.
- `apply_error` contains the failure reason if the latest reconciliation pass failed.
- `disabled_reason` indicates why a device's peer is currently excluded from the kernel (such as `paused`, `outside_pools`, or `key_expired`), or `null` when the peer is enabled.

## Error responses

Errors use RFC 9457 Problem Details (`application/problem+json`):

```json
{
  "type": "/api/v1/problems/pool_exhausted",
  "title": "No free block of the requested size.",
  "status": 409,
  "code": "pool_exhausted",
  "instance": "urn:uuid:…",
  "detail": "…"
}
```

Clients should branch on `code`. The `Problem` schema lists all error codes with their HTTP status and title. `detail`, when present, describes the specific validation or conflict failure for the request, and `instance` contains the request UUID (also returned in the `x-request-id` header and recorded in the server logs). Internal server errors omit `detail` and record the cause in the server logs only.

When a browser navigation request sends `Accept: text/html` first, the server renders the web application's error page with the same HTTP status code instead of returning raw JSON.

## Device keys and agent login

A device record persists until deleted, while its WireGuard public key expires `key_lifetime` after it was last set. Within 60 seconds after a key expires, the reconciler removes the peer from the kernel until a key is set or renewed. Keys can be managed either from the browser or through `ito-agent`.

### Browser-managed keys

The browser generates a WireGuard key pair locally, registers the public key with `POST /api/v1/devices/{id}/key` (or sends `{}` to renew the current key), and fetches `GET /api/v1/devices/{id}/config` to assemble a downloadable `wg-quick` configuration file with the local private key.

### Agent login and key rotation

An agent obtains its credential through an interactive browser approval flow:

1. The agent generates a WireGuard key pair and a 32-byte random secret encoded as unpadded base64url. It computes the request ID as the lowercase hex SHA-256 digest of the secret and opens `PUBLIC_URL/connect?id=<id>&t=<unix_seconds>` in the user's browser.
2. Within 15 minutes of `t`, the signed-in user approves the request for a specific device via `POST /api/v1/devices/{id}/claims`.
3. The agent polls `POST /api/v1/agent/claim` with its secret and WireGuard public key. The server returns `202 Accepted` until the request is approved, and then returns `200 OK` with the device view and a new bearer token (`itoa_<secret>`), binding the agent's public key to the device.
4. The agent polls `GET /api/v1/agent/config` until `"ready": true` and configures the local WireGuard interface.
5. Within 3 days of `key_expires_at`, the agent renews or rotates its WireGuard key via `POST /api/v1/agent/key`.

Pending claim approvals are held in memory for 10 minutes, up to 5 concurrent approvals per account. Repeating `POST /api/v1/agent/claim` within 2 minutes of the initial claim issues a replacement credential so an agent can recover from a dropped response.

Each device has at most one active agent credential; claiming a device replaces any previous credential. A key held by any other device is refused with `key_conflict`, even within the same account. To reuse it, first revoke or delete that device, or give it a different key.
