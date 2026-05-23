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
// MBEDTLS module
//
// Purpose: Implements the cryptographic functions used by fp-provider using the
// MBEDTLS package developed by ARM.
//
// To use the package, uncomment the NEARBY_PLATFORM_USE_MBEDTLS define in
// config.mk.
//
// The following features are implemented here:
//
// nearby_platform_Sha256Start(), nearby_platform_Sha256Update(),
// nearby_platform_Sha256Finish()
//
//     Implements the SHA function across and arbitrary length block. Partial
//     blocks can be sent, and the resulting SHA will be over all blocks.
//
// nearby_platform_Aes128Encrypt(), nearby_platform_Aes128Decrypt()
//
//     Encrypt and decrypt a block of data with a given key.
//
// Note that the required function nearby_platform_GenSec256r1Secret() is in a
// separate file, gen_secret.c.
//

#if defined(__has_include)
#if __has_include(<psa/crypto.h>)
#define NEARBY_PLATFORM_USE_PSA_CRYPTO 1
#endif
#endif

#if defined(NEARBY_PLATFORM_USE_PSA_CRYPTO)
#include <psa/crypto.h>
#else
#include <mbedtls/aes.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h> /* generic interface */
#include <mbedtls/sha256.h>
#if (MBEDTLS_VERSION_NUMBER >= 0x03000000)
#include <mbedtls/compat-2.x.h>
#endif
#endif

#include <nearby_platform_se.h>

#if defined(NEARBY_PLATFORM_USE_PSA_CRYPTO)
static psa_hash_operation_t sha256_op = PSA_HASH_OPERATION_INIT;

static nearby_platform_status nearby_platform_InitCrypto() {
  return psa_crypto_init() == PSA_SUCCESS ? kNearbyStatusOK : kNearbyStatusError;
}

nearby_platform_status nearby_platform_Sha256Start() {
  if (nearby_platform_InitCrypto() != kNearbyStatusOK) {
    return kNearbyStatusError;
  }
  psa_hash_abort(&sha256_op);
  return psa_hash_setup(&sha256_op, PSA_ALG_SHA_256) == PSA_SUCCESS ? kNearbyStatusOK
                                                                    : kNearbyStatusError;
}

nearby_platform_status nearby_platform_Sha256Update(const void* data,
                                                    size_t length) {
  return psa_hash_update(&sha256_op, (const uint8_t*)data, length) == PSA_SUCCESS
             ? kNearbyStatusOK
             : kNearbyStatusError;
}

nearby_platform_status nearby_platform_Sha256Finish(uint8_t out[32]) {
  size_t out_length = 0;
  psa_status_t status = psa_hash_finish(&sha256_op, out, 32, &out_length);
  if (status != PSA_SUCCESS || out_length != 32) {
    psa_hash_abort(&sha256_op);
    return kNearbyStatusError;
  }
  return kNearbyStatusOK;
}

static nearby_platform_status nearby_platform_Aes128Crypt(
    const uint8_t input[AES_MESSAGE_SIZE_BYTES],
    uint8_t output[AES_MESSAGE_SIZE_BYTES],
    const uint8_t key[AES_MESSAGE_SIZE_BYTES], psa_key_usage_t usage) {
  if (nearby_platform_InitCrypto() != kNearbyStatusOK) {
    return kNearbyStatusError;
  }

  nearby_platform_status platform_status = kNearbyStatusError;
  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_key_id_t key_id = 0;
  size_t output_length = 0;

  psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attributes, 128);
  psa_set_key_usage_flags(&attributes, usage);
  psa_set_key_algorithm(&attributes, PSA_ALG_ECB_NO_PADDING);

  psa_status_t status = psa_import_key(&attributes, key, AES_MESSAGE_SIZE_BYTES, &key_id);
  psa_reset_key_attributes(&attributes);
  if (status != PSA_SUCCESS) {
    goto exit;
  }

  if (usage == PSA_KEY_USAGE_ENCRYPT) {
    status = psa_cipher_encrypt(key_id, PSA_ALG_ECB_NO_PADDING, input,
                                AES_MESSAGE_SIZE_BYTES, output, AES_MESSAGE_SIZE_BYTES,
                                &output_length);
  } else {
    status = psa_cipher_decrypt(key_id, PSA_ALG_ECB_NO_PADDING, input,
                                AES_MESSAGE_SIZE_BYTES, output, AES_MESSAGE_SIZE_BYTES,
                                &output_length);
  }

  if (status == PSA_SUCCESS && output_length == AES_MESSAGE_SIZE_BYTES) {
    platform_status = kNearbyStatusOK;
  }

exit:
  if (key_id != 0) {
    psa_destroy_key(key_id);
  }
  return platform_status;
}

nearby_platform_status nearby_platform_Aes128Encrypt(
    const uint8_t input[AES_MESSAGE_SIZE_BYTES],
    uint8_t output[AES_MESSAGE_SIZE_BYTES],
    const uint8_t key[AES_MESSAGE_SIZE_BYTES]) {
  return nearby_platform_Aes128Crypt(input, output, key, PSA_KEY_USAGE_ENCRYPT);
}

nearby_platform_status nearby_platform_Aes128Decrypt(
    const uint8_t input[AES_MESSAGE_SIZE_BYTES],
    uint8_t output[AES_MESSAGE_SIZE_BYTES],
    const uint8_t key[AES_MESSAGE_SIZE_BYTES]) {
  return nearby_platform_Aes128Crypt(input, output, key, PSA_KEY_USAGE_DECRYPT);
}
#else
static mbedtls_sha256_context sha256_ctx;

nearby_platform_status nearby_platform_Sha256Start() {
  nearby_platform_status status = kNearbyStatusError;
  mbedtls_sha256_init(&sha256_ctx);
  if (mbedtls_sha256_starts_ret(&sha256_ctx, 0) == 0) {
    status = kNearbyStatusOK;
  } else {
    mbedtls_sha256_free(&sha256_ctx);
  }
  return status;
}

nearby_platform_status nearby_platform_Sha256Update(const void* data,
                                                    size_t length) {
  nearby_platform_status status = kNearbyStatusError;
  if (mbedtls_sha256_update_ret(&sha256_ctx, (const unsigned char*)data,
                                length) == 0) {
    status = kNearbyStatusOK;
  } else {
    mbedtls_sha256_free(&sha256_ctx);
  }
  return status;
}

nearby_platform_status nearby_platform_Sha256Finish(uint8_t out[32]) {
  nearby_platform_status status = kNearbyStatusError;
  if (mbedtls_sha256_finish_ret(&sha256_ctx, out) == 0) {
    status = kNearbyStatusOK;
  }
  mbedtls_sha256_free(&sha256_ctx);
  return status;
}

/**
 * Encrypts a data block with AES128 in ECB mode.
 */
nearby_platform_status nearby_platform_Aes128Encrypt(
    const uint8_t input[AES_MESSAGE_SIZE_BYTES],
    uint8_t output[AES_MESSAGE_SIZE_BYTES],
    const uint8_t key[AES_MESSAGE_SIZE_BYTES]) {
  nearby_platform_status status = kNearbyStatusError;
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  if (mbedtls_aes_setkey_enc(&ctx, key, 128) != 0) goto exit;
  if (mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, input, output) != 0)
    goto exit;
  status = kNearbyStatusOK;
exit:
  mbedtls_aes_free(&ctx);
  return status;
}

/**
 * Decrypts a data block with AES128 in ECB mode.
 */
nearby_platform_status nearby_platform_Aes128Decrypt(
    const uint8_t input[AES_MESSAGE_SIZE_BYTES],
    uint8_t output[AES_MESSAGE_SIZE_BYTES],
    const uint8_t key[AES_MESSAGE_SIZE_BYTES]) {
  nearby_platform_status status = kNearbyStatusError;
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  if (mbedtls_aes_setkey_dec(&ctx, key, 128) != 0) goto exit;
  if (mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, input, output) != 0)
    goto exit;
  status = kNearbyStatusOK;
exit:
  mbedtls_aes_free(&ctx);
  return status;
}
#endif
