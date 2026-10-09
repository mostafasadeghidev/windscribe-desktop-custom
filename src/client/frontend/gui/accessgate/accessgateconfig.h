#pragma once

#include <QtGlobal>

// Access gate server (Cloudflare worker, see worker/ in the wind project) and the Ed25519 public key
// that verifies its signed status responses (worker/keys/public_key.txt).
namespace AccessGateConfig {

inline constexpr const char *kServerUrl = "https://wind-gate.throbbing-boat-c9fc.workers.dev";
inline constexpr const char *kPublicKeyBase64 = "gXvJ2s3svrexi3YOwl0hNIT+7kJJQz2x0qFIYjPdbFs=";

// Retry delays after a failed check, before falling back to the server-provided interval.
inline constexpr int kRetryDelaysSec[] = { 60, 5 * 60, 15 * 60 };
// A session never expires with wall-clock time; only an explicit signed revocation ends it. As a guard
// against blocking the access server on purpose, the device is locked after this much app running time
// without a single valid answer. Time while the app is closed or the computer sleeps is not counted.
inline constexpr qint64 kMaxUnreachableMs = 7LL * 24 * 60 * 60 * 1000;
// How often unreachable time is accumulated, the largest step one tick may add (larger gaps are sleep
// or a stalled event loop), and how often accumulated time is persisted while unreachable.
inline constexpr int kUnreachableTickMs = 10 * 1000;
inline constexpr qint64 kUnreachableMaxStepMs = 30 * 1000;
inline constexpr int kUnreachableSaveEveryTicks = 6;

}
