.. |supported| replace:: **Supported**

.. |notsupported| replace:: Not supported

.. _crypto_driver_oberon:

nrf_oberon PSA Crypto driver
############################

Cryptographic operations
************************

Message digests (Hashes)
------------------------

.. list-table:: Supported hash algorithms
   :header-rows: 1

   * - Hash algorithm
     - PSA algorithm id
     - Support status

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
     - |notsupported|

   * - SHA-3 256
     - ``PSA_ALG_SHA3_256``
     - |notsupported|

   * - SHA-3 384
     - ``PSA_ALG_SHA3_384``
     - |notsupported|

   * - SHA-3 512
     - ``PSA_ALG_SHA3_512``
     - |notsupported|

   * - SHAKE256/512
     - ``PSA_ALG_SHAKE256_512``
     - |notsupported|

TODO! Do we need to specify we support both single part and multi part?

Message authentication codes (MAC)
----------------------------------

.. list-table:: Supported MAC ciphers
   :header-rows: 1

   * - MAC cipher
     - PSA algorithm id
     - Support status

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
     - PSA algorithm id
     - Support status

   * - Stream cipher
     - ``PSA_ALG_STREAM_CIPHER``
     - |supported|

   * - CTR
     - ``PSA_ALG_CTR``
     - |supported|

   * - CCM* no tag
     - ``PSA_ALG_CCM_STAR_NO_TAG``
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

"CCM* no tag" supported! TODO add to all drivers

TODO break down stream cipher to chacha, xchacha and arc4

TODO single part/multi part

Authenticated encryption with additional data (AEAD)
----------------------------------------------------

.. list-table:: Supported AEAD algorithms
   :header-rows: 1

   * - AEAD algorithm
     - PSA algorithm id
     - Support status
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
     - PSA algorithm id
     - Support status

   * - HKDF
     - ``PSA_ALG_HKDF(hash_alg)``
     - |supported|

   * - HKDF-Extract
     - ``PSA_ALG_HKDF_EXTRACT(hash_alg)``
     - |supported|

   * - HKDF-Expand
     - ``PSA_ALG_HKDF_EXPAND(hash_alg)``
     - |supported|

   * - SP 800-108 HMAC with counter
     - ``PSA_ALG_SP800_108_COUNTER_HMAC(hash_alg)``
     - |notsupported|

   * - SP 800-108r1 CMAC with counter
     - ``PSA_ALG_SP800_108_COUNTER_CMAC``
     - |notsupported|

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
     - PSA algorithm id
     - Support status

   * - RSA PKCS#1 v1.5 sign
     - ``PSA_ALG_RSA_PKCS1V15_SIGN(hash_alg)``
     - |supported|

   * - RSA raw PKCS#1 v1.5 sign
     - ``PSA_ALG_RSA_PKCS1V15_SIGN_RAW``
     - |supported|

   * - RSA PSS
     - ``PSA_ALG_RSA_PSS``
     - |supported|

   * - RSA PSS any salt
     - ``PSA_ALG_RSA_PSS_ANY_SALT``
     - |supported|

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
     - PSA algorithm id
     - Support status

   * - RSA PKCS#1 v1.5 crypt
     - ``PSA_ALG_RSA_PKCS1V15_CRYPT``
     - |supported|

   * - RSA OAEP
     - ``PSA_ALG_RSA_OAEP(hash_alg)``
     - |supported|

TODO! Note that RSA key pair generation is not supported

Key agreement
-------------

.. list-table:: Supported key agreement algorithms
   :header-rows: 1

   * - Key agreement algorithm
     - PSA algorithm id
     - Support status

   * - FFDH
     - ``PSA_ALG_FFDH``
     - |notsupported|

   * - ECDH
     - ``PSA_ALG_ECDH``
     - |supported|

TODO! Note: The nrf_oberon driver is currently limited to curve types secp224r1, secp256r1, secp384r1, and Curve25519 for ECDH.

Random number generation
------------------------

.. list-table:: PRNG algorithms
   :header-rows: 1

   * - PRNG algorithm
     - Configuration option

   * - CTR-DRBG
     - :kconfig:option:`CONFIG_PSA_WANT_ALG_CTR_DRBG`

   * - HMAC-DRBG
     - :kconfig:option:`CONFIG_PSA_WANT_ALG_HMAC_DRBG`



Note

* Both PRNG algorithms are NIST qualified Cryptographically Secure Pseudo Random Number Generators (CSPRNG).
* :kconfig:option:`CONFIG_PSA_WANT_ALG_CTR_DRBG` and :kconfig:option:`CONFIG_PSA_WANT_ALG_HMAC_DRBG` are custom configurations not described by the PSA Crypto specification.
* If multiple PRNG algorithms are enabled at the same time, CTR-DRBG will be prioritized for random number generation through the front-end APIs for PSA Crypto.

Supported! TODO revisit and redesign!

Password-authenticated key exchange (PAKE)
------------------------------------------

.. list-table:: Supported PAKE protocols
   :header-rows: 1

   * - PAKE protocol
     - PSA algorithm id
     - Support status

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
     - Support status

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
     - |notsupported|

   * - Brainpool320r1
     - ``PSA_ECC_FAMILY_BRAINPOOL_P_R1``
     - 320
     - |notsupported|

   * - Brainpool384r1
     - ``PSA_ECC_FAMILY_BRAINPOOL_P_R1``
     - 384
     - |notsupported|

   * - Brainpool512r1
     - ``PSA_ECC_FAMILY_BRAINPOOL_P_R1``
     - 512
     - |notsupported|

   * - Curve25519 (X25519)
     - ``PSA_ECC_FAMILY_MONTGOMERY``
     - 255
     - |supported|

   * - Curve448 (X448)
     - ``PSA_ECC_FAMILY_MONTGOMERY``
     - 448
     - |notsupported|

   * - Edwards25519 (Ed25519)
     - ``PSA_ECC_FAMILY_TWISTED_EDWARDS``
     - 255
     - |supported|

   * - Edwards448 (Ed448)
     - ``PSA_ECC_FAMILY_TWISTED_EDWARDS``
     - 448
     - |notsupported|

   * - secp192k1
     - ``PSA_ECC_FAMILY_SECP_K1``
     - 192
     - |notsupported|

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
     - |supported|

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
     - |notsupported|


``PSA_KEY_TYPE_ECC_KEY_PAIR`` or ``PSA_KEY_TYPE_ECC_PUBLIC_KEY``

TODO update

Key parameters
**************

Key types
---------

.. list-table:: Key type support
   :header-rows: 1

   * - Key type
     - PSA key type
     - Support status

   * - AES
     - ``PSA_KEY_TYPE_AES``
     - |supported|

   * - Chacha20
     - ``PSA_KEY_TYPE_CHACHA20``
     - |supported|

   * - ECC key pair
     - ``PSA_KEY_TYPE_ECC_KEY_PAIR(curve)``
     - |supported|

   * - ECC public key
     - ``PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve)``
     - |supported|

   * - RSA key pair
     - ``PSA_KEY_TYPE_RSA_KEY_PAIR``
     - |supported|

   * - RSA public key
     - ``PSA_KEY_TYPE_RSA_PUBLIC_KEY``
     - |supported|

   * - DH key pair
     - ``PSA_KEY_TYPE_DH_KEY_PAIR(group)``
     - |notsupported|

   * - DH public key
     - ``PSA_KEY_TYPE_DH_PUBLIC_KEY(group)``
     - |notsupported|

TODO Document that RSA key pair generation is not supported


Key sizes
---------

.. list-table:: Key size support, for key types that have a configurable size
   :header-rows: 1

   * - Key type
     - Key bits
     - nRF54L05 / L10 / L15

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
     - |supported|

   * - RSA
     - 1536 bits
     - |supported|

   * - RSA
     - 2048 bits
     - |supported|

   * - RSA
     - 3072 bits
     - |supported|

   * - RSA
     - 4096 bits
     - |supported|

   * - RSA
     - 6144 bits
     - |supported|

   * - RSA
     - 8192 bits
     - |supported|

Configuration
*************

driver configuration. Depends on nrf_security and oberon psa core

feature security. link to generic feature security page


TODO
