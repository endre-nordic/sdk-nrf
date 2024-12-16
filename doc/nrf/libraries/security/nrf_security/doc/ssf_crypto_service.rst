.. |supported| replace:: **Supported**

.. |notsupported| replace:: Not supported

.. _ssf_crypto_service:

SSF PSA Crypto service
######################

.. contents::
   :local:
   :depth: 2

SDFW Service framework crypto service is a blahblah.

.. _ssf_crypto_service_configuration:

Cryptographic operations
************************

Message digests (Hashes)
------------------------

.. list-table:: Supported hash algorithms
   :header-rows: 1

   * - Hash algorithm
     - PSA Algorithm id
     - nRF54H20

   * - SHA-1 (weak)
     - ``PSA_ALG_SHA_1``
     - |supported|

   * - SHA-224
     - ``PSA_ALG_SHA_224``
     - |supported|

   * - SHA-256
     - ``PSA_ALG_SHA_256``
     - |supported|

   * - SHA-384
     - ``PSA_ALG_SHA_384``
     - |supported|

   * - SHA-512
     - ``PSA_ALG_SHA_512``
     - |supported|

   * - SHA-512/224
     - ``PSA_ALG_SHA_512_224``
     - |notsupported|

   * - SHA-512/256
     - ``PSA_ALG_SHA_512_256``
     - |notsupported|

   * - SHA-3 224
     - ``PSA_ALG_SHA3_224``
     - |supported|

   * - SHA-3 256
     - ``PSA_ALG_SHA3_256``
     - |supported|

   * - SHA-3 384
     - ``PSA_ALG_SHA3_384``
     - |supported|

   * - SHA-3 512
     - ``PSA_ALG_SHA3_512``
     - |supported|

   * - SHAKE256/512
     - ``PSA_ALG_SHAKE256_512``
     - |notsupported| (TODO revisit!)

TODO! Do we need to specify we support both single part and multi part?

Message authentication codes (MAC)
----------------------------------

.. list-table:: Supported MAC ciphers
   :header-rows: 1

   * - MAC cipher
     - PSA Algorithm id
     - nRF54H20

   * - HMAC
     - ``PSA_ALG_HMAC(hash_alg)``
     - |supported|

   * - CMAC
     - ``PSA_ALG_CMAC``
     - |supported|

TODO single part/multi part?


Unauthenticated ciphers
-----------------------

.. list-table:: Supported cipher modes
   :header-rows: 1

   * - Cipher mode
     - PSA Algorithm id
     - nRF54H20

   * - Stream cipher
     - ``PSA_ALG_STREAM_CIPHER``
     - |notsupported|

   * - CTR
     - ``PSA_ALG_CTR``
     - |supported|

   * - ECB no padding
     - ``PSA_ALG_ECB_NO_PADDING``
     - |supported|

   * - CBC no padding
     - ``PSA_ALG_CBC_NO_PADDING``
     - |supported|

   * - CBC PKCS#7 padding
     - ``PSA_ALG_CBC_PKCS7``
     - |supported|

TODO single part/multi part

Authenticated encryption with additional data (AEAD)
----------------------------------------------------

.. list-table:: Supported AEAD algorithms
   :header-rows: 1

   * - AEAD algorithm
     - PSA Algorithm id
     - nRF54H20
     - Notes

   * - CCM
     - ``PSA_ALG_CCM``
     - |supported|
     - Tag sizes: 16, 15, 14, 13, 12, 8, 4

   * - GCM
     - ``PSA_ALG_GCM``
     - |supported|
     - Tag sizes: 16, 15, 14, 13, 12, 8, 4

   * - ChaCha20-Poly1305
     - ``PSA_ALG_CHACHA20_POLY1305``
     - |supported|
     - Tag size: 16

TODO revisit. How to clean up tag sizes?

TODO single part/multi part

Key derivation
--------------

.. list-table:: Supported key derivation functions
   :header-rows: 1

   * - Key derivation function
     - PSA Algorithm id
     - nRF54H20

   * - HKDF
     - ``PSA_ALG_HKDF(hash_alg)``
     - |supported|

   * - HKDF-Extract
     - ``PSA_ALG_HKDF_EXTRACT(hash_alg)``
     - |notsupported| (TODO revisit)

   * - HKDF-Expand
     - ``PSA_ALG_HKDF_EXPAND(hash_alg)``
     - |notsupported| (TODO revisit)

   * - SP 800-108 HMAC with counter
     - ``PSA_ALG_SP800_108_COUNTER_HMAC(hash_alg)``
     - |notsupported| (TODO revisit)

   * - SP 800-108r1 CMAC with counter
     - ``PSA_ALG_SP800_108_COUNTER_CMAC``
     - |supported|

   * - TLS 1.2 PRF
     - ``PSA_ALG_TLS12_PRF(hash_alg)``
     - |supported|

   * - TLS 1.2 PSK to MasterSecret
     - ``PSA_ALG_TLS12_PSK_TO_MS(hash_alg)``
     - |supported|

   * - TLS 1.2 EC J-PAKE to PMS
     - ``PSA_ALG_TLS12_ECJPAKE_TO_PMS``
     - |supported|

   * - PBKDF2-HMAC
     - ``PSA_ALG_PBKDF2_HMAC(hash_alg)``
     - |supported|

   * - PBKDF2-AES-CMAC-PRF-128
     - ``PSA_ALG_PBKDF2_AES_CMAC_PRF_128``
     - |supported|

Asymmetric signatures
---------------------

.. list-table:: Supported signature algorithms
   :header-rows: 1

   * - Asymmetric signature algorithm
     - PSA Algorithm id
     - nRF54H20

   * - RSA PKCS#1 v1.5 sign
     - ``PSA_ALG_RSA_PKCS1V15_SIGN(hash_alg)``
     - |notsupported|

   * - RSA raw PKCS#1 v1.5 sign
     - ``PSA_ALG_RSA_PKCS1V15_SIGN_RAW``
     - |notsupported|

   * - RSA PSS
     - ``PSA_ALG_RSA_PSS``
     - |notsupported|

   * - RSA PSS any salt
     - ``PSA_ALG_RSA_PSS_ANY_SALT``
     - |notsupported|

   * - ECDSA
     - ``PSA_ALG_ECDSA(hash_alg)``
     - |supported|

   * - ECDSA without hashing
     - ``PSA_ALG_ECDSA_ANY``
     - |supported|

   * - ECDSA deterministic
     - ``PSA_ALG_DETERMINISTIC_ECDSA(hash_alg)``
     - |supported|

   * - PureEdDSA
     - ``PSA_ALG_PURE_EDDSA``
     - |supported|

   * - HashEdDSA Edwards25519
     - ``PSA_ALG_ED25519PH``
     - |notsupported| (TODO revisit)

   * - HashEdDSA Edwards448
     - ``PSA_ALG_ED448PH``
     - |notsupported| (TODO revisit)

Asymmetric encryption
---------------------

.. list-table:: Supported asymmetric encryption algorithms
   :header-rows: 1

   * - Asymmetric encryption algorithm
     - PSA Algorithm id
     - nRF54H20

   * - RSA PKCS#1 v1.5 crypt
     - ``PSA_ALG_RSA_PKCS1V15_CRYPT``
     - |notsupported|

   * - RSA OAEP
     - ``PSA_ALG_RSA_OAEP(hash_alg)``
     - |notsupported|


Key agreement
-------------

.. list-table:: Supported key agreement algorithms
   :header-rows: 1

   * - Key agreement algorithm
     - PSA Algorithm id
     - nRF54H20

   * - FFDH
     - ``PSA_ALG_FFDH``
     - |notsupported|

   * - ECDH
     - ``PSA_ALG_ECDH``
     - |supported|

Random number generation
------------------------

Supported! TODO revisit and redesign!

Password-authenticated key exchange (PAKE)
------------------------------------------

.. list-table:: Supported PAKE protocols
   :header-rows: 1

   * - PAKE protocol
     - PSA Algorithm id
     - nRF54H20

   * - EC J-PAKE
     - ``PSA_ALG_JPAKE``
     - |supported|

   * - SPAKE2+ with HMAC
     - ``PSA_ALG_SPAKE2P_HMAC(hash_alg)``
     - |supported|

   * - SPAKE2+ with CMAC
     - ``PSA_ALG_SPAKE2P_CMAC``
     - |supported|

   * - SPAKE2+ for Matter
     - ``PSA_ALG_SPAKE2P_MATTER``
     - |supported|

   * - SRP-6
     - ``PSA_ALG_SRP_6``
     - |supported| (TODO check)

   * - SRP-6 password hashing
     - ``PSA_ALG_SRP_PASSWORD_HASH``
     - |supported| (TODO check)

TODO figure out how to list PSA parameters for PAKE

Elliptical curves
*****************

.. list-table:: Elliptical curve support
   :header-rows: 1

   * - Curve
     - PSA ECC Family
     - key_bits
     - nRF54L05/10/15

   * - Brainpool 192r1
     - ``PSA_ECC_FAMILY_BRAINPOOL_P_R1``
     - 192
     - |notsupported|

   * - Brainpool 224r1
     - ``PSA_ECC_FAMILY_BRAINPOOL_P_R1``
     - 224
     - |notsupported|

   * - Brainpool256r1
     - ``PSA_ECC_FAMILY_BRAINPOOL_P_R1``
     - 256
     - |supported|

   * - Brainpool320r1
     - ``PSA_ECC_FAMILY_BRAINPOOL_P_R1``
     - 320
     - |supported| (TODO check)

   * - Brainpool384r1
     - ``PSA_ECC_FAMILY_BRAINPOOL_P_R1``
     - 384
     - |supported|

   * - Brainpool512r1
     - ``PSA_ECC_FAMILY_BRAINPOOL_P_R1``
     - 512
     - |supported|

   * - Curve25519 (X25519)
     - ``PSA_ECC_FAMILY_MONTGOMERY``
     - 255
     - |supported|

   * - Curve448 (X448)
     - ``PSA_ECC_FAMILY_MONTGOMERY``
     - 448
     - |supported| (TODO check)

   * - Edwards25519 (Ed25519)
     - ``PSA_ECC_FAMILY_TWISTED_EDWARDS``
     - 255
     - |supported|

   * - Edwards448 (Ed448)
     - ``PSA_ECC_FAMILY_TWISTED_EDWARDS``
     - 448
     - |notsupported| (TODO check)

   * - secp192k1
     - ``PSA_ECC_FAMILY_SECP_K1``
     - 192
     - |supported| (TODO check)

   * - secp224k1
     - ``PSA_ECC_FAMILY_SECP_K1``
     - 224
     - |notsupported|

   * - secp256k1
     - ``PSA_ECC_FAMILY_SECP_K1``
     - 256
     - |notsupported|

   * - secp192r1
     - ``PSA_ECC_FAMILY_SECP_R1``
     - 192
     - |notsupported|

   * - secp224r1
     - ``PSA_ECC_FAMILY_SECP_R1``
     - 224
     - |notsupported|

   * - secp256r1
     - ``PSA_ECC_FAMILY_SECP_R1``
     - 256
     - |supported|

   * - secp384r1
     - ``PSA_ECC_FAMILY_SECP_R1``
     - 384
     - |supported|

   * - secp521r1
     - ``PSA_ECC_FAMILY_SECP_R1``
     - 521
     - |supported|

Key parameters
**************

Key types
---------

.. list-table:: Supported key types
   :header-rows: 1

   * - Key type
     - psa_key_type_t
     - nRF54H20

   * - AES
     - PSA_KEY_TYPE_AES
     - |supported|

   * - Chacha20
     - PSA_KEY_TYPE_CHACHA20
     - |supported|

   * - ECC key pair
     - PSA_KEY_TYPE_ECC_KEY_PAIR(curve)
     - |supported|

   * - ECC public key
     - PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve)
     - |supported|

   * - RSA key pair
     - PSA_KEY_TYPE_RSA_KEY_PAIR
     - |notsupported|

   * - RSA public key
     - PSA_KEY_TYPE_RSA_PUBLIC_KEY
     - |notsupported|

   * - DH key pair
     - PSA_KEY_TYPE_DH_KEY_PAIR(group)
     - |notsupported|

   * - DH public key
     - PSA_KEY_TYPE_DH_PUBLIC_KEY(group)
     - |notsupported|

Key sizes
---------

.. list-table:: Supported AES key sizes
   :header-rows: 1

   * - Key type
     - Key bits
     - nRF54H20

   * - AES
     - 128 bits
     - |supported|

   * - AES
     - 192 bits
     - |supported|

   * - AES
     - 256 bits
     - |supported|

   * - RSA
     - 1024 bits
     - |notsupported|

   * - RSA
     - 1536 bits
     - |notsupported|

   * - RSA
     - 2048 bits
     - |notsupported|

   * - RSA
     - 3072 bits
     - |notsupported|

   * - RSA
     - 4096 bits
     - |notsupported|

   * - RSA
     - 6144 bits
     - |notsupported|

   * - RSA
     - 8192 bits
     - |notsupported|

Configuration
*************

soemthing about enabling SSF
mention that PSA_WANT functionality is "baked in"
