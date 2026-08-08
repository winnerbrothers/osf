/*
 * osf.h — C ABI for the OSF core (weapon/UAV/UGV firmware, C/C++, PHP ext).
 *
 * Link against libosf_core (cdylib) or the static archive. All hash outputs
 * are 64 lowercase hex chars + NUL; pass a buffer of >= 65 bytes as `out`.
 * Functions return 0 (OSF_OK) on success, negative on error.
 *
 * Rights: Winner Brothers Group / LEE JUNGHOON / PCT WO 2025/127469 A1.
 */
#ifndef OSF_H
#define OSF_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OSF_OK        0
#define OSF_ERR_NULL (-1)
#define OSF_ERR_UTF8 (-2)
#define OSF_ERR_ENV  (-3)

#define OSF_HEX_LEN  64  /* bytes, excluding NUL */
#define OSF_OUT_LEN  65  /* provide at least this for `out` */

/* H(s_K(t) || nonce). coords/axis point to 3 doubles each; nonce may be NULL. */
int osf_state_hash(const double *coords,
                   const double *axis,
                   double angular_speed,
                   int64_t initial_timestamp_ms,
                   int64_t timestamp_ms,
                   const char *nonce /* nullable */,
                   char *out /* >= OSF_OUT_LEN */);

/* HMAC-SHA-256 command signature (defense path). */
int osf_command_sign(const char *session_key_hex,
                     const char *command,
                     const char *sender_state_hash,
                     const char *nonce,
                     int64_t ts_ms,
                     const char *cmd_id,
                     char *out /* >= OSF_OUT_LEN */);

/* Returns 1 valid, 0 invalid, negative on error. Constant-time compare. */
int osf_command_verify(const char *session_key_hex,
                       const char *command,
                       const char *sender_state_hash,
                       const char *nonce,
                       int64_t ts_ms,
                       const char *cmd_id,
                       const char *signature_hex);

/* Δ (ms) for an environment: gps_disciplined|datacenter|lan|field|satellite|space */
int osf_delta_ms(const char *environment, double *out);

/* Static version string, e.g. "0.1.0". */
const char *osf_version(void);

#ifdef __cplusplus
}
#endif

#endif /* OSF_H */
