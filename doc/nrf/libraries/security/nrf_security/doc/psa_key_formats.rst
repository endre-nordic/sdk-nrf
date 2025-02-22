.. _nrf_psa_key_formats:

PSA Crypto key formats
######################

The PSA Crypto API has requirements for the binary format for keys that will be imported using `psa_import_key`,
and for how they are exported using `psa_export_key` and `psa_export_public_key`.
These requirements are specified in section 9.6.4 in the `PSA Certified Crypto API <PSA Certified Crypto API 1.2.1>`_.

TODO Call to action! Intent of this page. Help people convert keys and generate them in the right format.

A summary of the requirements are included below, and some assistance for how to generate or convert key files to a
binary format appropriate for importing.

.. note::
   Properly managing cryptographic secrets is important to the security of your product. The advice provided below is
   intended to aid a developer during a *development phase* of a project.
   If possible, we recommend you use or derive keys that are not exportable from the cryptograhic HW, or that you
   generate keys on the device during production. If during the production phase you must generate and import keys
   off-device, please take appropriate measures to protect the cryptographic secrets.

Key types
*********

RSA
===

something about which keys types are supported in psa crypto

Generating an RSA key pair file
-------------------------------
The command below creates a file :file:`keypair_pkcs1.pem` with a 2048 bit private key. The "-traditional` flag
specifices that the output should be PKCS#1 formatted. Without this flag, openssl will store the key in PKCS#8 format.

.. code-block:: console

    openssl genrsa -out keypair.pem -traditional 2048

Extracting an importable RSA key pair
-------------------------------------

The PSA Crypto key type `PSA_KEY_TYPE_RSA_KEY_PAIR` requires that the data is stored as the non-encrypted DER
encoding of the representation defined in PKCS #1: RSA Cryptography Specifications Version 2.2 as `RSAPrivateKey`,
version 0.

Ensure that the output is DER, and that the encoding is PKCS#1 (-traditional)

.. code-block:: console

    openssl rsa -inform PEM -outform DER -in keypair.pem -out keypair_pkcs1.der -traditional

Extracting an importable RSA public key
---------------------------------------

The key type `PSA_KEY_TYPE_RSA_PUBLIC_KEY` requires the key data stored as the DER encoding of the representation
defined by Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and
Certificate Revocation List (CRL) Profile §2.3.1 as RSAPublicKey.

Creates :file:`public_pkcs1.der` containing the DER encoded RSA public key.

.. code-block:: console

    openssl rsa -inform PEM -outform DER -in keypair.pem -out public_pkcs1.der -RSAPublicKey_out -traditional

Elliptical curves (Weierstrass curves)
======================================

Something about nist

Generating an ECC key pair file
-------------------------------

The command below use openssl to generate a key pair for a secp256r1 curve, matching the PSA key type
PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1) with key_bits set to 256.

.. code-block:: console

   openssl ecparam -name secp256r1 -genkey -noout -out ec_keypair.pem

For additional curve names that can follow the `-name` parameter, execute this command to see which
named curve types are supported in openssl.

.. code-block:: console

   openssl ecparam -list_curves

Extracting an importable ECC key pair
-------------------------------------

PSA_KEY_TYPE_ECC_KEY_PAIR(ecc_family), where ecc_family designates a Weierstrass curve family.
The key data is the content of the privateKey field of the ECPrivateKey format defined by Elliptic Curve Private Key Structure [RFC5915].
This is a [m/8]-byte string in big-endian order, where is the key size in bits.

To extract the private key in a format suitable for importing, follow the steps below:

#. Convert the PEM file to DER.

   .. code-block:: console

      openssl ec -inform PEM -outform DER -in ec_keypair.pem -out ec_keypair.der

#. Dump the ASN.1 contents of the output file.

   .. code-block:: console

      openssl asn1parse -inform DER -in ec_keypair.der

#. Identify the byte location in the ASN.1 DER encoding, containing the key.

   Find a line containing `OCTET STRING   [HEX DUMP]:xxxxxxx` and make a note of the number in the first line.

   For example: `5:d=1  hl=2 l=  32 prim: OCTET STRING      [HEX DUMP]:132F7EAxxx`

#. Extract the key, starting with the byte from the number highlighted above.

   .. code-block:: console

      openssl asn1parse -inform DER -in ec_keypair.der -out raw_key.bin -noout -strparse 5

Extracting an importable ECC public key
---------------------------------------

PSA_KEY_TYPE_ECC_PUBLIC_KEY(ecc_family), where ecc_family designates a Weierstrass curve family.

The key data is the uncompressed representation of an elliptic curve point as an octet string defined in SEC 1: Elliptic Curve Cryptography [SEC1] §2.3.3. If m is the bit size associated with the curve, i.e. the bit size of for a curve over Fq, then the representation of point P consists of:

The byte 0x04;

xp as a [m/8]-byte-string, big-endian;

yp as a [m/8]-byte-string, big-endian;

#. Store the public key as DER

   .. code-block:: console

      openssl ec -in ec_keypair.pem -pubout -outform DER -out ec_public.der

#. Dump the contents
+
   .. code-block:: console

      openssl asn1parse -in ec_pub.der -inform DER

#. Identify the byte location of the public key

   Find 23:d=1  hl=2 l=  66 prim: BIT STRING

   .. code-block:: console

      openssl asn1parse -inform DER -in ec_pub.der -out public_key.raw -noout -strparse 23

Elliptical curves (Twisted Edwards)
===================================

Ed25519 and Ed448
