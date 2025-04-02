/**
 * picoEC.h - Elliptic Curve Cryptography Library for Raspberry Pi Pico
 * 
 * A lightweight elliptic curve encryption, decryption, and digital signature
 * library for Raspberry Pi Pico W using the Arduino-Pico core which includes BearSSL.
 * 
 * Based on BearSSL (https://bearssl.org/) by Thomas Pornin
 */

 #ifndef PICO_EC_H
 #define PICO_EC_H
 
 #include <Arduino.h>
 #include "bearssl/bearssl.h"
 
 /**
  * @brief Supported curve identifiers
  * 
  * These match the BearSSL curve identifiers but we only include the most common ones.
  */
 enum PicoECCurve {
     EC_SECP256R1 = BR_EC_secp256r1,  // NIST P-256
     EC_SECP384R1 = BR_EC_secp384r1,  // NIST P-384
     EC_SECP521R1 = BR_EC_secp521r1,  // NIST P-521
     EC_CURVE25519 = BR_EC_curve25519 // Curve25519 (for ECDH)
 };
 
 /**
  * @brief Signature formats
  */
 enum PicoECSignatureFormat {
     EC_SIGNATURE_RAW,   // Raw R|S format
     EC_SIGNATURE_ASN1   // ASN.1 DER encoding
 };
 
 /**
  * @brief PicoEC class for elliptic curve cryptography operations
  */
 class PicoEC {
 private:
     PicoECCurve _curve;                 // Selected curve
     const br_ec_impl *_ec_impl;         // BearSSL EC implementation
     br_ec_private_key _private_key;     // Private key 
     br_ec_public_key _public_key;       // Public key
     unsigned char *_private_key_buf;    // Buffer for private key
     unsigned char *_public_key_buf;     // Buffer for public key
     size_t _private_key_len;            // Length of private key buffer
     size_t _public_key_len;             // Length of public key buffer
     br_ecdsa_sign _sign_impl_asn1;      // ASN.1 signature implementation
     br_ecdsa_sign _sign_impl_raw;       // Raw signature implementation
     br_ecdsa_vrfy _verify_impl_asn1;    // ASN.1 verify implementation
     br_ecdsa_vrfy _verify_impl_raw;     // Raw verify implementation
     bool _has_keys;                     // Whether keys have been generated
     
     // Random number generator context
     br_hmac_drbg_context _rng_ctx;
     br_prng_seeder _seeder; // Function pointer to our entropy source
 
     // Temporary buffer for ECDH shared secret and other operations
     unsigned char *_tmp_buffer;
     size_t _tmp_buffer_len;
     
     // Internal methods
     void initializeImplementation();
     void cleanupKeys();
     size_t getCurveMaxSize() const;
     
 public:
     /**
      * @brief Construct a new PicoEC object
      * @param curve The curve to use (default: EC_SECP256R1)
      */
     PicoEC(PicoECCurve curve = EC_SECP256R1);
     
     /**
      * @brief Destroy the PicoEC object and free resources
      */
     ~PicoEC();
     
     /**
      * @brief Generate a new EC key pair
      * @param collectEntropy Whether to automatically collect entropy from analog pins
      * @return true if key generation was successful
      */
     bool generateKeyPair(bool collectEntropy = true);
     
     /**
      * @brief Load private key from buffer
      * @param privateKey Pointer to private key data
      * @param keyLength Length of private key data
      * @return true if key was loaded successfully
      */
     bool loadPrivateKey(const uint8_t* privateKey, size_t keyLength);
     
     /**
      * @brief Load public key from buffer
      * @param publicKey Pointer to public key data
      * @param keyLength Length of public key data
      * @return true if key was loaded successfully
      */
     bool loadPublicKey(const uint8_t* publicKey, size_t keyLength);
     
     /**
      * @brief Get the private key
      * @param buffer Buffer to copy the private key into
      * @param maxLen Maximum length of the buffer
      * @return Length of the copied key or 0 on error
      */
     size_t getPrivateKey(uint8_t* buffer, size_t maxLen) const;
     
     /**
      * @brief Get the public key
      * @param buffer Buffer to copy the public key into
      * @param maxLen Maximum length of the buffer
      * @return Length of the copied key or 0 on error
      */
     size_t getPublicKey(uint8_t* buffer, size_t maxLen) const;
     
     /**
      * @brief Sign a message or hash with the private key
      * @param message Pointer to the message or hash to sign
      * @param messageLen Length of the message
      * @param signature Buffer to receive the signature
      * @param maxSignatureLen Maximum length of the signature buffer
      * @param format Signature format (EC_SIGNATURE_RAW or EC_SIGNATURE_ASN1)
      * @param isHash true if message is a pre-computed hash, false for raw message
      * @return Length of the signature or 0 on error
      */
     size_t sign(const uint8_t* message, size_t messageLen, 
                uint8_t* signature, size_t maxSignatureLen,
                PicoECSignatureFormat format = EC_SIGNATURE_ASN1,
                bool isHash = false);
     
     /**
      * @brief Verify a signature with the public key
      * @param message Pointer to the message or hash that was signed
      * @param messageLen Length of the message
      * @param signature Pointer to the signature to verify
      * @param signatureLen Length of the signature
      * @param format Signature format (EC_SIGNATURE_RAW or EC_SIGNATURE_ASN1)
      * @param isHash true if message is a pre-computed hash, false for raw message
      * @return true if the signature is valid
      */
     bool verify(const uint8_t* message, size_t messageLen,
                const uint8_t* signature, size_t signatureLen,
                PicoECSignatureFormat format = EC_SIGNATURE_ASN1,
                bool isHash = false);
     
     /**
      * @brief Perform Elliptic Curve Diffie-Hellman key exchange
      * @param peerPublicKey Pointer to the peer's public key
      * @param peerKeyLen Length of the peer's public key
      * @param sharedSecret Buffer to receive the shared secret
      * @param maxSecretLen Maximum length of the shared secret buffer
      * @return Length of the shared secret or 0 on error
      */
     size_t computeSharedSecret(const uint8_t* peerPublicKey, size_t peerKeyLen,
                               uint8_t* sharedSecret, size_t maxSecretLen);
     
     /**
      * @brief Add additional entropy to the random number generator
      * @param seed Pointer to the seed data
      * @param seedLen Length of the seed data
      */
     void addEntropy(const uint8_t* seed, size_t seedLen);
     
     /**
      * @brief Calculate the maximum signature length for the current curve and format
      * @param format Signature format (EC_SIGNATURE_RAW or EC_SIGNATURE_ASN1)
      * @return Maximum signature length in bytes
      */
     size_t getMaxSignatureLength(PicoECSignatureFormat format) const;
     
     /**
      * @brief Check if keys have been generated or loaded
      * @return true if keys are available
      */
     bool hasKeys() const;
     
     /**
      * @brief Get the current curve
      * @return The current curve identifier
      */
     PicoECCurve getCurve() const;
     
     /**
      * @brief Change the curve to use
      * @param curve New curve to use
      * @return true if the curve was changed successfully
      */
     bool setCurve(PicoECCurve curve);
     
     /**
      * @brief Convert a signature from raw to ASN.1 format
      * @param signature Pointer to the signature buffer (in-place conversion)
      * @param signatureLen Pointer to the signature length, updated after conversion
      * @return true if conversion was successful
      */
     static bool convertRawToAsn1(uint8_t* signature, size_t* signatureLen);
     
     /**
      * @brief Convert a signature from ASN.1 to raw format
      * @param signature Pointer to the signature buffer (in-place conversion)
      * @param signatureLen Pointer to the signature length, updated after conversion
      * @return true if conversion was successful
      */
     static bool convertAsn1ToRaw(uint8_t* signature, size_t* signatureLen);
 };
 
 #endif // PICO_EC_H