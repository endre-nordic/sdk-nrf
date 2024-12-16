.. |supported| replace:: **Supported**

.. |notsupported| replace:: Not supported

.. _crypto_driver_cc3xx:

nrf_cc3xx PSA Crypto driver
###########################

The nrf_cc3xx PSA crypto driver supports the Cryptocell 310 and the Cryptocell 312 HW crypto accellerators.
There are some differences in the capabilities and limitations of these two revisions. Feature support
will vary depending on which product you use.

.. list-table:: Cryptocell product reference
   :header-rows: 1

   * - Product name
     - HW accellerator

   * - nRF52840
     - Cryptocell 310

   * - nRF91xx series
     - Cryptocell 310

   * - nRF5340
     - Cryptocell 312

TODO rephrase. The Arm CryptoCell cc3xx driver allows enabling or disabling of specific PSA APIs (such as psa_cipher_encrypt, psa_sign_hash), but not individual algorithms.

Cryptographic operations
************************

.. _crypto_driver_cc3xx_hashes:

Message digests (Hashes)
------------------------

.. list-table:: Supported hash algorithms
   :header-rows: 1

   * - Hash algorithm
     - PSA algorithm id
     - nRF52840
     - nRF91xx series
     - nRF5340

   * - SHA-1 (weak)
     - ``PSA_ALG_SHA_1``
     - |supported|
     - |supported|
     - |supported|

   * - SHA-224
     - ``PSA_ALG_SHA_224``
     - |supported|
     - |supported|
     - |supported|

   * - SHA-256
     - ``PSA_ALG_SHA_256``
     - |supported|
     - |supported|
     - |supported|

   * - SHA-384
     - ``PSA_ALG_SHA_384``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - SHA-512
     - ``PSA_ALG_SHA_512``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - SHA-512/224
     - ``PSA_ALG_SHA_512_224``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - SHA-512/256
     - ``PSA_ALG_SHA_512_256``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - SHA-3 224
     - ``PSA_ALG_SHA3_224``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - SHA-3 256
     - ``PSA_ALG_SHA3_256``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - SHA-3 384
     - ``PSA_ALG_SHA3_384``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - SHA-3 512
     - ``PSA_ALG_SHA3_512``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - SHAKE256/512
     - ``PSA_ALG_SHAKE256_512``
     - |notsupported|
     - |notsupported|
     - |notsupported|

Message authentication codes (MAC)
----------------------------------

.. list-table:: Supported MAC ciphers
   :header-rows: 1

   * - MAC cipher
     - PSA algorithm id
     - nRF52840
     - nRF91xx series
     - nRF5340

   * - HMAC :ref:`(1) <crypto_driver_cc3xx_mac_note>`
     - ``PSA_ALG_HMAC(hash_alg)``
     - |supported|
     - |supported|
     - |supported|

   * - CMAC
     - ``PSA_ALG_CMAC``
     - |supported| :ref:`(2) <crypto_driver_cc3xx_mac_note>`
     - |supported| :ref:`(2) <crypto_driver_cc3xx_mac_note>`
     - |supported|

.. _crypto_driver_cc3xx_mac_note:

.. note::
   \(1) HMAC support is limited to the list of supported hash algorithms. See :ref:`Message digests (Hashes) <crypto_driver_cc3xx_hashes>`.

   \(2) Some products only support 128 bit AES keys. See :ref:`key sizes <crypto_driver_cc3xx_key_sizes>` for details.

Unauthenticated ciphers
-----------------------

.. list-table:: Supported cipher modes
   :header-rows: 1

   * - Cipher mode
     - PSA algorithm id
     - nRF52840
     - nRF91xx series
     - nRF5340

   * - Stream cipher
     - ``PSA_ALG_STREAM_CIPHER``
     - |supported|
     - |supported|
     - |supported|

   * - CTR
     - ``PSA_ALG_CTR``
     - |supported| :ref:`* <crypto_driver_cc3xx_cipher_key_size_note>`
     - |supported| :ref:`* <crypto_driver_cc3xx_cipher_key_size_note>`
     - |supported|

   * - CCM* no tag
     - ``PSA_ALG_CCM_STAR_NO_TAG``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - ECB no padding
     - ``PSA_ALG_ECB_NO_PADDING``
     - |supported| :ref:`* <crypto_driver_cc3xx_cipher_key_size_note>`
     - |supported| :ref:`* <crypto_driver_cc3xx_cipher_key_size_note>`
     - |supported|

   * - CBC no padding
     - ``PSA_ALG_CBC_NO_PADDING``
     - |supported| :ref:`* <crypto_driver_cc3xx_cipher_key_size_note>`
     - |supported| :ref:`* <crypto_driver_cc3xx_cipher_key_size_note>`
     - |supported|

   * - CBC PKCS#7 padding
     - ``PSA_ALG_CBC_PKCS7``
     - |supported| :ref:`* <crypto_driver_cc3xx_cipher_key_size_note>`
     - |supported| :ref:`* <crypto_driver_cc3xx_cipher_key_size_note>`
     - |supported|

.. _crypto_driver_cc3xx_cipher_key_size_note:

.. note::
   \* Some products only support 128 bit AES keys. See :ref:`key sizes <crypto_driver_cc3xx_key_sizes>` for details.

Authenticated encryption with additional data (AEAD)
----------------------------------------------------

.. list-table:: Supported AEAD algorithms
   :header-rows: 1

   * - AEAD algorithm
     - PSA algorithm id
     - nRF52840
     - nRF91xx series
     - nRF5340
     - Notes

   * - CCM
     - ``PSA_ALG_CCM``
     - |supported| :ref:`* <crypto_driver_cc3xx_cipher_key_size_note>`
     - |supported| :ref:`* <crypto_driver_cc3xx_cipher_key_size_note>`
     - |supported|
     - Tag sizes: 16, 15, 14, 13, 12, 8, 4

   * - GCM
     - ``PSA_ALG_GCM``
     - |notsupported|
     - |notsupported|
     - |supported|
     - Tag sizes: 16, 15, 14, 13, 12, 8, 4

   * - ChaCha20-Poly1305
     - ``PSA_ALG_CHACHA20_POLY1305``
     - |supported|
     - |supported|
     - |supported|
     - Tag size: 16

.. _crypto_driver_cc3xx_aead_key_size_note:

.. note::
   \* Some products only support 128 bit AES keys. See :ref:`key sizes <crypto_driver_cc3xx_key_sizes>` for details.

TODO revisit. How to clean up tag sizes?

TODO single part/multi part

Key derivation
--------------

.. list-table:: Supported key derivation functions
   :header-rows: 1

   * - Key derivation function
     - PSA algorithm id
     - nRF52840
     - nRF91xx series
     - nRF5340

   * - HKDF
     - ``PSA_ALG_HKDF(hash_alg)``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - HKDF-Extract
     - ``PSA_ALG_HKDF_EXTRACT(hash_alg)``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - HKDF-Expand
     - ``PSA_ALG_HKDF_EXPAND(hash_alg)``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - SP 800-108 HMAC with counter
     - ``PSA_ALG_SP800_108_COUNTER_HMAC(hash_alg)``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - SP 800-108r1 CMAC with counter
     - ``PSA_ALG_SP800_108_COUNTER_CMAC``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - TLS 1.2 PRF
     - ``PSA_ALG_TLS12_PRF(hash_alg)``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - TLS 1.2 PSK to MasterSecret
     - ``PSA_ALG_TLS12_PSK_TO_MS(hash_alg)``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - TLS 1.2 EC J-PAKE to PMS
     - ``PSA_ALG_TLS12_ECJPAKE_TO_PMS``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - PBKDF2-HMAC
     - ``PSA_ALG_PBKDF2_HMAC(hash_alg)``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - PBKDF2-AES-CMAC-PRF-128
     - ``PSA_ALG_PBKDF2_AES_CMAC_PRF_128``
     - |notsupported|
     - |notsupported|
     - |notsupported|

Asymmetric signatures
---------------------

.. list-table:: Supported signature algorithms
   :header-rows: 1

   * - Asymmetric signature algorithm
     - PSA algorithm id
     - nRF52840
     - nRF91xx series
     - nRF5340

   * - RSA PKCS#1 v1.5 sign
     - ``PSA_ALG_RSA_PKCS1V15_SIGN(hash_alg)``
     - |supported|
     - |supported|
     - |supported|

   * - RSA raw PKCS#1 v1.5 sign
     - ``PSA_ALG_RSA_PKCS1V15_SIGN_RAW``
     - |supported|
     - |supported|
     - |supported|

   * - RSA PSS
     - ``PSA_ALG_RSA_PSS``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - RSA PSS any salt
     - ``PSA_ALG_RSA_PSS_ANY_SALT``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - ECDSA
     - ``PSA_ALG_ECDSA(hash_alg)``
     - |supported|
     - |supported|
     - |supported|

   * - ECDSA without hashing
     - ``PSA_ALG_ECDSA_ANY``
     - |supported|
     - |supported|
     - |supported|

   * - ECDSA deterministic
     - ``PSA_ALG_DETERMINISTIC_ECDSA(hash_alg)``
     - |supported|
     - |supported|
     - |supported|

   * - PureEdDSA
     - ``PSA_ALG_PURE_EDDSA``
     - |supported|
     - |supported|
     - |supported|

   * - HashEdDSA Edwards25519
     - ``PSA_ALG_ED25519PH``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - HashEdDSA Edwards448
     - ``PSA_ALG_ED448PH``
     - |notsupported|
     - |notsupported|
     - |notsupported|

Asymmetric encryption
---------------------

.. list-table:: Supported asymmetric encryption algorithms
   :header-rows: 1

   * - Asymmetric encryption algorithm
     - PSA algorithm id
     - nRF52840
     - nRF91xx series
     - nRF5340

   * - RSA PKCS#1 v1.5 crypt
     - ``PSA_ALG_RSA_PKCS1V15_CRYPT``
     - |supported|
     - |supported|
     - |supported|

   * - RSA OAEP
     - ``PSA_ALG_RSA_OAEP(hash_alg)``
     - |supported|
     - |supported|
     - |supported|

Key agreement
-------------

.. list-table:: Supported key agreement algorithms
   :header-rows: 1

   * - Key agreement algorithm
     - PSA algorithm id
     - nRF52840
     - nRF91xx series
     - nRF5340

   * - FFDH
     - ``PSA_ALG_FFDH``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - ECDH
     - ``PSA_ALG_ECDH``
     - |supported|
     - |supported|
     - |supported|

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

TODO! When using CryptoCell, only 1024 bytes can be requested at a time.

TODO! For devices without a hardware-accelerated cryptographic engine, entropy is provided by the nRF RNG peripheral. PRNG support is provided by the Oberon PSA driver, which is implemented using software.

Password-authenticated key exchange (PAKE)
------------------------------------------

.. list-table:: Supported PAKE protocols
   :header-rows: 1

   * - PAKE protocol
     - PSA algorithm id
     - nRF52840
     - nRF91xx series
     - nRF5340

   * - EC J-PAKE
     - ``PSA_ALG_JPAKE``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - SPAKE2+ with HMAC
     - ``PSA_ALG_SPAKE2P_HMAC(hash_alg)``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - SPAKE2+ with CMAC
     - ``PSA_ALG_SPAKE2P_CMAC``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - SPAKE2+ for Matter
     - ``PSA_ALG_SPAKE2P_MATTER``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - SRP-6
     - ``PSA_ALG_SRP_6``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - SRP-6 password hashing
     - ``PSA_ALG_SRP_PASSWORD_HASH``
     - |notsupported|
     - |notsupported|
     - |notsupported|

TODO figure out how to list PSA parameters for PAKE

Elliptical curves
*****************

.. list-table:: Elliptical curve support
   :header-rows: 1

   * - Curve
     - PSA ECC Family
     - key_bits
     - nRF52840
     - nRF91xx series
     - nRF5340

   * - Brainpool 192r1
     - ``PSA_ECC_FAMILY_BRAINPOOL_P_R1``
     - 192
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - Brainpool 224r1
     - ``PSA_ECC_FAMILY_BRAINPOOL_P_R1``
     - 224
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - Brainpool256r1
     - ``PSA_ECC_FAMILY_BRAINPOOL_P_R1``
     - 256
     - |supported|
     - |supported|
     - |supported|

   * - Brainpool320r1
     - ``PSA_ECC_FAMILY_BRAINPOOL_P_R1``
     - 320
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - Brainpool384r1
     - ``PSA_ECC_FAMILY_BRAINPOOL_P_R1``
     - 384
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - Brainpool512r1
     - ``PSA_ECC_FAMILY_BRAINPOOL_P_R1``
     - 512
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - Curve25519 (X25519)
     - ``PSA_ECC_FAMILY_MONTGOMERY``
     - 255
     - |supported|
     - |supported|
     - |supported|

   * - Curve448 (X448)
     - ``PSA_ECC_FAMILY_MONTGOMERY``
     - 448
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - Edwards25519 (Ed25519)
     - ``PSA_ECC_FAMILY_TWISTED_EDWARDS``
     - 255
     - |supported|
     - |supported|
     - |supported|

   * - Edwards448 (Ed448)
     - ``PSA_ECC_FAMILY_TWISTED_EDWARDS``
     - 448
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - secp192k1
     - ``PSA_ECC_FAMILY_SECP_K1``
     - 192
     - |supported|
     - |supported|
     - |supported|

   * - secp224k1
     - ``PSA_ECC_FAMILY_SECP_K1``
     - 224
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - secp256k1
     - ``PSA_ECC_FAMILY_SECP_K1``
     - 256
     - |supported|
     - |supported|
     - |supported|

   * - secp192r1
     - ``PSA_ECC_FAMILY_SECP_R1``
     - 192
     - |supported|
     - |supported|
     - |supported|

   * - secp224r1
     - ``PSA_ECC_FAMILY_SECP_R1``
     - 224
     - |supported|
     - |supported|
     - |supported|

   * - secp256r1
     - ``PSA_ECC_FAMILY_SECP_R1``
     - 256
     - |supported|
     - |supported|
     - |supported|

   * - secp384r1
     - ``PSA_ECC_FAMILY_SECP_R1``
     - 384
     - |supported|
     - |supported|
     - |supported|

   * - secp521r1
     - ``PSA_ECC_FAMILY_SECP_R1``
     - 521
     - |notsupported|
     - |notsupported|
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
     - nRF52840
     - nRF91xx series
     - nRF5340

   * - AES
     - ``PSA_KEY_TYPE_AES``
     - |supported|
     - |supported|
     - |supported|

   * - Chacha20
     - ``PSA_KEY_TYPE_CHACHA20``
     - |supported|
     - |supported|
     - |supported|

   * - ECC key pair
     - ``PSA_KEY_TYPE_ECC_KEY_PAIR(curve)``
     - |supported|
     - |supported|
     - |supported|

   * - ECC public key
     - ``PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve)``
     - |supported|
     - |supported|
     - |supported|

   * - RSA key pair
     - ``PSA_KEY_TYPE_RSA_KEY_PAIR``
     - |supported|
     - |supported|
     - |supported|

   * - RSA public key
     - ``PSA_KEY_TYPE_RSA_PUBLIC_KEY``
     - |supported|
     - |supported|
     - |supported|

   * - DH key pair
     - ``PSA_KEY_TYPE_DH_KEY_PAIR(group)``
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - DH public key
     - ``PSA_KEY_TYPE_DH_PUBLIC_KEY(group)``
     - |notsupported|
     - |notsupported|
     - |notsupported|

.. _crypto_driver_cc3xx_key_sizes:

Key sizes
---------

.. list-table:: Key size support, for key types that have a configurable size
   :header-rows: 1

   * - Key type
     - Key bits
     - nRF52840
     - nRF91xx series
     - nRF5340

   * - AES
     - 128 bits
     - |supported|
     - |supported|
     - |supported|

   * - AES
     - 192 bits
     - |notsupported|
     - |notsupported|
     - |supported|

   * - AES
     - 256 bits
     - |notsupported|
     - |notsupported|
     - |supported|

   * - RSA
     - 1024 bits
     - |supported|
     - |supported|
     - |supported|

   * - RSA
     - 1536 bits
     - |supported|
     - |supported|
     - |supported|

   * - RSA
     - 2048 bits
     - |supported|
     - |supported|
     - |supported|

   * - RSA
     - 3072 bits
     - |notsupported|
     - |notsupported|
     - |supported|

   * - RSA
     - 4096 bits
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - RSA
     - 6144 bits
     - |notsupported|
     - |notsupported|
     - |notsupported|

   * - RSA
     - 8192 bits
     - |notsupported|
     - |notsupported|
     - |notsupported|

TODO! Mention that 1024 RSA is not recommended

Limitations
***********

cc310: Doesn't support DMA to flash. Make sure you provide input and output pointers to RAM.

Configuration
*************

:kconfig:option:`CONFIG_PSA_CRYPTO_DRIVER_CC3XX`