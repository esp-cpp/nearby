// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//
// gen_secret module
//
// Implements the nearby_platform_GenSec256r1Secret() function, using the
// MBEDTLS package developed by ARM.
//
// To use the package, uncomment the NEARBY_PLATFORM_USE_MBEDTLS define in
// config.mk.
//
// This routine was separated from the mbedtls.c code because an implementation
// may need to implement the shared secret function using a hardware embedded
// key. In such an implementation, the actual private key is not directly
// accessable, but rather the shared secret is generated using the public key
// and the sequestered private key without ever revealing the private key in
// code.
//

#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#if defined(__has_include)
#if __has_include(<psa/crypto.h>)
#define NEARBY_PLATFORM_USE_PSA_CRYPTO 1
#endif
#endif

#if defined(NEARBY_PLATFORM_USE_PSA_CRYPTO)
#include <psa/crypto.h>
#include <string.h>
#else
#include <mbedtls/aes.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h> /* generic interface */
#include <mbedtls/sha256.h>
#if (MBEDTLS_VERSION_NUMBER >= 0x03000000)
#include <mbedtls/compat-2.x.h>
#endif
#endif

#include <nearby_platform_se.h>
#include <stdlib.h>

#ifndef NEARBY_PLATFORM_HAS_SE
#if defined(NEARBY_PLATFORM_USE_PSA_CRYPTO)
static nearby_platform_status nearby_platform_InitCrypto() {
  return psa_crypto_init() == PSA_SUCCESS ? kNearbyStatusOK : kNearbyStatusError;
}

nearby_platform_status nearby_platform_GenSec256r1Secret(
    const uint8_t remote_party_public_key[64], uint8_t shared_secret[32]) {
  if (nearby_platform_InitCrypto() != kNearbyStatusOK) {
    return kNearbyStatusError;
  }

  const uint8_t* pkp = nearby_platform_GetAntiSpoofingPrivateKey();
  if (!pkp) {
    return kNearbyStatusError;
  }

  nearby_platform_status platform_status = kNearbyStatusError;
  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_key_id_t key_id = 0;
  size_t shared_secret_length = 0;
  uint8_t peer_public_key[65] = {0x04};

  memcpy(&peer_public_key[1], remote_party_public_key, 64);

  psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
  psa_set_key_bits(&attributes, 256);
  psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
  psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);

  psa_status_t status = psa_import_key(&attributes, pkp, 32, &key_id);
  psa_reset_key_attributes(&attributes);
  if (status != PSA_SUCCESS) {
    goto exit;
  }

  status = psa_raw_key_agreement(PSA_ALG_ECDH, key_id, peer_public_key, sizeof(peer_public_key),
                                 shared_secret, 32, &shared_secret_length);
  if (status == PSA_SUCCESS && shared_secret_length == 32) {
    platform_status = kNearbyStatusOK;
  }

exit:
  if (key_id != 0) {
    psa_destroy_key(key_id);
  }
  return platform_status;
}
#else
static int crypto_rand(void* const seed, uint8_t* const out,
                       size_t const size) {
  (void)seed;
  for (size_t i = 0; i < size; i++) {
    out[i] = rand() % UINT8_MAX;
  }
  return 0;
}

/**
 * Generates a shared sec256p1 secret using remote party public key and this
 * device's private key.
 */
nearby_platform_status nearby_platform_GenSec256r1Secret(
    const uint8_t remote_party_public_key[64], uint8_t shared_secret[32]) {
  nearby_platform_status status = kNearbyStatusError;
  mbedtls_ecp_group grp;
  mbedtls_ecp_point pub;
  mbedtls_mpi prv;
  mbedtls_mpi secret;

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&pub);
  mbedtls_mpi_init(&prv);
  mbedtls_mpi_init(&secret);

  mbedtls_mpi_uint p = 1;
  pub.Z.p = &p;
  pub.Z.n = 1;

  const uint8_t* pkp;

  pkp = nearby_platform_GetAntiSpoofingPrivateKey();
  if (!pkp) {
    goto exit;
  }
  if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) goto exit;
  if (mbedtls_mpi_read_binary(&pub.X, remote_party_public_key, 32) != 0)
    goto exit;
  if (mbedtls_mpi_read_binary(&pub.Y, remote_party_public_key + 32, 32) != 0)
    goto exit;
  if (mbedtls_mpi_read_binary(&prv, pkp, 32) != 0) goto exit;
  if ((mbedtls_ecdh_compute_shared(&grp, &secret, &pub, &prv, crypto_rand,
                                   NULL)) != 0)
    goto exit;
  if (mbedtls_mpi_write_binary(&secret, shared_secret, 32) != 0) goto exit;

  status = kNearbyStatusOK;

exit:
  pub.Z.p = NULL;
  pub.Z.n = 0;

  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&pub);
  mbedtls_mpi_free(&prv);
  mbedtls_mpi_free(&secret);

  return status;
}
#endif
#endif /* NEARBY_PLATFORM_HAS_SE */
