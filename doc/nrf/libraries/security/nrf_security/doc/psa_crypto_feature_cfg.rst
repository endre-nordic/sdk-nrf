.. _psa_crypto_feature_configuration:

PSA Crypto feature configuration
################################

.. contents::
   :local:
   :depth: 2

Configuration system introduced by Mbed TLS.

Adopted by Oberon PSA core

Dead code removal

Driver architecture

Also used by by libraries to enable/disable functionality based on crypto availability. For instance tls and x509.

enable/disable using psa PSA_WANT

list available PSA functions

not all functionality is available for all drivers

some drivers use these terms to conditionally include support for crypto functionality

Configuration options
*********************

Random number generation
========================

:kconfig:option:`PSA_WANT_GENERATE_RANDOM``
   Enable support for :c:func:`psa_generate_random`.

:kconfig:option:`PSA_WANT_ALG_CTR_DRBG`
   Use CTR_DRBG as pseudorandom number generator function for random numbers in :c:func:`psa_get_random`

:kconfig:option:`PSA_WANT_ALG_HMAC_DRBG`
   Use HMAC_DRBG as pseudorandom number generator function for random numbers in :c:func:`psa_get_random`

   TODO just keep this description in cracen driver?

.. _psa_crypto_feature_configuration_key_types:

Key types
=========

* :kconfig:option:`PSA_WANT_KEY_TYPE_PASSWORD`
* :kconfig:option:`PSA_WANT_KEY_TYPE_PASSWORD_HASH`
* :kconfig:option:`PSA_WANT_KEY_TYPE_PEPPER`
* :kconfig:option:`PSA_WANT_KEY_TYPE_RAW_DATA`
* :kconfig:option:`PSA_WANT_KEY_TYPE_DERIVE`
* :kconfig:option:`PSA_WANT_KEY_TYPE_HMAC`
* :kconfig:option:`PSA_WANT_KEY_TYPE_AES`
* :kconfig:option:`PSA_WANT_KEY_TYPE_CHACHA20`
* :kconfig:option:`PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY`
* :kconfig:option:`PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC`
* :kconfig:option:`PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT`
* :kconfig:option:`PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT`
* :kconfig:option:`PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE`
* :kconfig:option:`PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE`
* :kconfig:option:`PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY`
* :kconfig:option:`PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC`
* :kconfig:option:`PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT`
* :kconfig:option:`PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT`
* :kconfig:option:`PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE`
* :kconfig:option:`PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_DERIVE`
* :kconfig:option:`PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_IMPORT`
* :kconfig:option:`PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_EXPORT`
* :kconfig:option:`PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_GENERATE`
* :kconfig:option:`PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_DERIVE`
* :kconfig:option:`PSA_WANT_KEY_TYPE_SPAKE2P_PUBLIC_KEY`
* :kconfig:option:`PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_IMPORT`
* :kconfig:option:`PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_EXPORT`
* :kconfig:option:`PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_GENERATE`
* :kconfig:option:`PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_DERIVE`
* :kconfig:option:`PSA_WANT_KEY_TYPE_SRP_PUBLIC_KEY`

.. _psa_crypto_feature_configuration_key_sizes:

Key sizes
=========

* :kconfig:option:`PSA_WANT_AES_KEY_SIZE_128`
* :kconfig:option:`PSA_WANT_AES_KEY_SIZE_192`
* :kconfig:option:`PSA_WANT_AES_KEY_SIZE_256`
* :kconfig:option:`PSA_WANT_RSA_KEY_SIZE_1024`
* :kconfig:option:`PSA_WANT_RSA_KEY_SIZE_1536`
* :kconfig:option:`PSA_WANT_RSA_KEY_SIZE_2048`
* :kconfig:option:`PSA_WANT_RSA_KEY_SIZE_3072`
* :kconfig:option:`PSA_WANT_RSA_KEY_SIZE_4096`
* :kconfig:option:`PSA_WANT_RSA_KEY_SIZE_6144`
* :kconfig:option:`PSA_WANT_RSA_KEY_SIZE_8192`

Ciphers
=======

* :kconfig:option:`PSA_WANT_ALG_STREAM_CIPHER`
* :kconfig:option:`PSA_WANT_ALG_ECB_NO_PADDING`
* :kconfig:option:`PSA_WANT_ALG_CBC_NO_PADDING`
* :kconfig:option:`PSA_WANT_ALG_CBC_PKCS7`
* :kconfig:option:`PSA_WANT_ALG_CTR`
* :kconfig:option:`PSA_WANT_ALG_XTS`
* :kconfig:option:`PSA_WANT_ALG_CHACHA20`
* :kconfig:option:`PSA_WANT_ALG_CCM_STAR_NO_TAG`



MAC
===

When configuring MAC algorithm, the application additionally needs to enable the
required :ref:`key type <psa_crypto_feature_configuration_key_types>`
and :ref:`key size(s) <psa_crypto_feature_configuration_key_sizes>`.

.. list-table:: MAC configuration
   :header-rows: 1

   * - MAC algorithm
     - Config option
     - Key type required
     - Supported key sizes

   * - AES-CMAC
     - :kconfig:option:`PSA_WANT_ALG_CMAC`
     - :kconfig:option:`PSA_WANT_KEY_TYPE_AES`
     - * :kconfig:option:`PSA_WANT_AES_KEY_SIZE_128`
       * :kconfig:option:`PSA_WANT_AES_KEY_SIZE_192`
       * :kconfig:option:`PSA_WANT_AES_KEY_SIZE_256`

   * - HMAC
     - :kconfig:option:`PSA_WANT_ALG_HMAC`
     - :kconfig:option:`PSA_WANT_KEY_TYPE_HMAC`
     -


Authenticated encryption with additional data
=============================================

* :kconfig:option:`PSA_WANT_ALG_CCM`
* :kconfig:option:`PSA_WANT_ALG_CHACHA20_POLY1305`
* :kconfig:option:`PSA_WANT_ALG_GCM`

Hash
====

.. list-table:: Hash feature configurations
   :header-rows: 1

   * - Algorithm family
     - Configuration directive

   * - SHA-1
     - :kconfig:option:`PSA_WANT_ALG_SHA_1`

   * - SHA-2 224
     - :kconfig:option:`PSA_WANT_ALG_SHA_224`

   * - SHA-2 256
     - :kconfig:option:`PSA_WANT_ALG_SHA_256`

   * - SHA-2 384
     - :kconfig:option:`PSA_WANT_ALG_SHA_384`

   * - SHA-2 512
     - :kconfig:option:`PSA_WANT_ALG_SHA_512`

   * - SHA-3 224
     - :kconfig:option:`PSA_WANT_ALG_SHA3_224`

   * - SHA-3 256
     - :kconfig:option:`PSA_WANT_ALG_SHA3_256`

   * - SHA-3 384
     - :kconfig:option:`PSA_WANT_ALG_SHA3_384`

   * - SHA-3 512
     - :kconfig:option:`PSA_WANT_ALG_SHA3_512`

   * - SHA-3 512/224
     - :kconfig:option:`PSA_WANT_ALG_SHA_512_224`

   * - SHA-3 512/256
     - :kconfig:option:`PSA_WANT_ALG_SHA_512_256`

   * - SHAKE
     - :kconfig:option:`PSA_WANT_ALG_SHAKE256_512`

Key agreement
=============

* :kconfig:option:`PSA_WANT_ALG_ECDH`
* :kconfig:option:`PSA_WANT_ALG_FFDH`

Asymmetric signature
====================

* :kconfig:option:`PSA_WANT_ALG_DETERMINISTIC_ECDSA`
* :kconfig:option:`PSA_WANT_ALG_ECDSA`
* :kconfig:option:`PSA_WANT_ALG_ECDSA_ANY`
* :kconfig:option:`PSA_WANT_ALG_ED25519PH`
* :kconfig:option:`PSA_WANT_ALG_ED448PH`
* :kconfig:option:`PSA_WANT_ALG_PURE_EDDSA`
* :kconfig:option:`PSA_WANT_ALG_RSA_PKCS1V15_SIGN`
* :kconfig:option:`PSA_WANT_ALG_RSA_PKCS1V15_SIGN_RAW`
* :kconfig:option:`PSA_WANT_ALG_RSA_PSS_ANY_SALT`
* :kconfig:option:`PSA_WANT_ALG_RSA_PSS`

Elliptical curves
=================

.. rst-class:: rst-columns

* :kconfig:option:`PSA_WANT_ECC_BRAINPOOL_P_R1_160`
* :kconfig:option:`PSA_WANT_ECC_BRAINPOOL_P_R1_192`
* :kconfig:option:`PSA_WANT_ECC_BRAINPOOL_P_R1_224`
* :kconfig:option:`PSA_WANT_ECC_BRAINPOOL_P_R1_320`
* :kconfig:option:`PSA_WANT_ECC_MONTGOMERY_255`
* :kconfig:option:`PSA_WANT_ECC_MONTGOMERY_448`
* :kconfig:option:`PSA_WANT_ECC_TWISTED_EDWARDS_255`
* :kconfig:option:`PSA_WANT_ECC_TWISTED_EDWARDS_448`
* :kconfig:option:`PSA_WANT_ECC_SECP_K1_224`
* :kconfig:option:`PSA_WANT_ECC_SECP_R2_160`
* :kconfig:option:`PSA_WANT_ECC_SECT_K1_163`
* :kconfig:option:`PSA_WANT_ECC_SECT_K1_233`
* :kconfig:option:`PSA_WANT_ECC_SECT_K1_239`
* :kconfig:option:`PSA_WANT_ECC_SECT_K1_283`
* :kconfig:option:`PSA_WANT_ECC_SECT_K1_409`
* :kconfig:option:`PSA_WANT_ECC_SECT_K1_571`
* :kconfig:option:`PSA_WANT_ECC_SECT_R1_163`
* :kconfig:option:`PSA_WANT_ECC_SECT_R1_233`
* :kconfig:option:`PSA_WANT_ECC_SECT_R1_283`
* :kconfig:option:`PSA_WANT_ECC_SECT_R1_409`
* :kconfig:option:`PSA_WANT_ECC_SECT_R1_571`
* :kconfig:option:`PSA_WANT_ECC_SECT_R2_163`
* :kconfig:option:`PSA_WANT_ECC_FRP_V1_256`
* :kconfig:option:`PSA_WANT_ECC_SECP_R1_224`
* :kconfig:option:`PSA_WANT_ECC_SECP_R1_256`
* :kconfig:option:`PSA_WANT_ECC_SECP_R1_384`
* :kconfig:option:`PSA_WANT_ECC_SECP_R1_521`

Key derivation
==============

* :kconfig:option:`PSA_WANT_ALG_HKDF`
* :kconfig:option:`PSA_WANT_ALG_HKDF_EXTRACT`
* :kconfig:option:`PSA_WANT_ALG_HKDF_EXPAND`
* :kconfig:option:`PSA_WANT_ALG_PBKDF2_HMAC`
* :kconfig:option:`PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128`
* :kconfig:option:`PSA_WANT_ALG_SP800_108_COUNTER_CMAC`
* :kconfig:option:`PSA_WANT_ALG_SP800_108_COUNTER_HMAC`
* :kconfig:option:`PSA_WANT_ALG_TLS12_PRF`
* :kconfig:option:`PSA_WANT_ALG_TLS12_PSK_TO_MS`
* :kconfig:option:`PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS`


Asymmetric encryption
=====================

* :kconfig:option:`PSA_WANT_ALG_RSA_OAEP`
* :kconfig:option:`PSA_WANT_ALG_RSA_PKCS1V15_CRYPT`

Password-authenticated key exchange
===================================

* :kconfig:option:`PSA_WANT_ALG_JPAKE`
* :kconfig:option:`PSA_WANT_ALG_SPAKE2P`
* :kconfig:option:`PSA_WANT_ALG_SPAKE2P_HMAC`
* :kconfig:option:`PSA_WANT_ALG_SPAKE2P_CMAC`
* :kconfig:option:`PSA_WANT_ALG_SPAKE2P_MATTER`
* :kconfig:option:`PSA_WANT_ALG_SRP_6`
* :kconfig:option:`PSA_WANT_ALG_SRP_PASSWORD_HASH`
