#pragma once

#include <QtGlobal>

// Access gate server (Cloudflare worker, see worker/ in the wind project) and the Ed25519 public key
// that verifies its signed status responses (worker/keys/public_key.txt).
namespace AccessGateConfig {

inline constexpr const char *kServerUrl = "https://wind-gate.throbbing-boat-c9fc.workers.dev";
inline constexpr const char *kPublicKeyBase64 = "gXvJ2s3svrexi3YOwl0hNIT+7kJJQz2x0qFIYjPdbFs=";

// Retry delays after a failed check, before falling back to the server-provided interval.
inline constexpr int kRetryDelaysSec[] = { 60, 5 * 60, 15 * 60 };
// Tolerated backwards jump of the local clock before the offline grace is considered void.
inline constexpr qint64 kClockSkewToleranceMs = 5 * 60 * 1000;

}
