/**
 * picoEC.cpp - Elliptic Curve Cryptography Library for Raspberry Pi Pico
 * 
 * Implementation of the picoEC library functions.
 */

 #include "picoEC.h"

 // SHA-256 implementation for hashing
 static const br_hash_class *sha256_impl = &br_sha256_vtable;
 
 // Collect entropy from Arduino analog pins - must match br_prng_seeder type
 static int pico_entropy_source(const br_prng_class **ctx, void *data, size_t len) {
     // Cast void* to unsigned char*
     unsigned char *output = (unsigned char *)data;
     size_t collected = 0;
     
     // Use analog readings as entropy source
     while (collected < len) {
         // Read from floating analog pins for randomness
         uint32_t val = analogRead(A0 + (collected % 4));
         
         // Get current micros for additional entropy
         val ^= micros();
         
         // Add timing jitter for additional randomness
         delay(1);
         val ^= micros();
         
         // Use the value in the output
         size_t to_use = len - collected;
         if (to_use > sizeof(val)) {
             to_use = sizeof(val);
         }
         
         memcpy(data + collected, &val, to_use);
         collected += to_use;
     }
     
     return 1; // Success
 }
 
 PicoEC::PicoEC(PicoECCurve curve) 
     : _curve(curve), 
       _ec_impl(nullptr),
       _private_key_buf(nullptr),
       _public_key_buf(nullptr),
       _private_key_len(0),
       _public_key_len(0),
       _sign_impl_asn1(nullptr),
       _sign_impl_raw(nullptr),
       _verify_impl_asn1(nullptr),
       _verify_impl_raw(nullptr),
       _has_keys(false),
       _tmp_buffer(nullptr),
       _tmp_buffer_len(0) {
     
     // Initialize the implementation based on curve
     initializeImplementation();
     
     // Configure the PRNG with our entropy source
     _seeder = (br_prng_seeder)pico_entropy_source;
     
     // Initialize HMAC-DRBG
     br_hmac_drbg_init(&_rng_ctx, sha256_impl, NULL, 0);
     
     // Warm up the PRNG
     uint8_t seed[32];
     for (int i = 0; i < 32; i++) {
         seed[i] = analogRead(A0 + (i % 4)) & 0xFF;
     }
     br_hmac_drbg_update(&_rng_ctx, seed, sizeof(seed));
     
     // Allocate temporary buffer
     _tmp_buffer_len = getCurveMaxSize() * 2;
     _tmp_buffer = (unsigned char *)malloc(_tmp_buffer_len);
 }
 
 PicoEC::~PicoEC() {
     // Clean up keys and buffers
     cleanupKeys();
     
     if (_tmp_buffer != nullptr) {
         free(_tmp_buffer);
         _tmp_buffer = nullptr;
     }
 }
 
 void PicoEC::initializeImplementation() {
     // Select EC implementation
     _ec_impl = br_ec_get_default();
     
     // Initialize signature/verification implementations
     _sign_impl_asn1 = br_ecdsa_sign_asn1_get_default();
     _sign_impl_raw = br_ecdsa_sign_raw_get_default();
     _verify_impl_asn1 = br_ecdsa_vrfy_asn1_get_default();
     _verify_impl_raw = br_ecdsa_vrfy_raw_get_default();
     
     // Reset keys
     _private_key.curve = _curve;
     _private_key.x = nullptr;
     _private_key.xlen = 0;
     
     _public_key.curve = _curve;
     _public_key.q = nullptr;
     _public_key.qlen = 0;
 }
 
 size_t PicoEC::getCurveMaxSize() const {
     // Return appropriate curve size in bytes
     switch (_curve) {
         case EC_SECP256R1:
             return 32;
         case EC_SECP384R1:
             return 48;
         case EC_SECP521R1:
             return 66;
         case EC_CURVE25519:
             return 32;
         default:
             return 32; // Default to 256-bit
     }
 }
 
 void PicoEC::cleanupKeys() {
     // Free key buffers if they exist
     if (_private_key_buf != nullptr) {
         free(_private_key_buf);
         _private_key_buf = nullptr;
     }
     
     if (_public_key_buf != nullptr) {
         free(_public_key_buf);
         _public_key_buf = nullptr;
     }
     
     _private_key.x = nullptr;
     _private_key.xlen = 0;
     _public_key.q = nullptr;
     _public_key.qlen = 0;
     
     _has_keys = false;
 }
 
 bool PicoEC::generateKeyPair(bool collectEntropy) {
     // Clean up existing keys
     cleanupKeys();
     
     // Add additional entropy if requested
     if (collectEntropy) {
         uint8_t entropy[32];
         for (int i = 0; i < 32; i++) {
             entropy[i] = analogRead(A0 + (i % 4)) & 0xFF;
         }
         br_hmac_drbg_update(&_rng_ctx, entropy, sizeof(entropy));
     }
     
     // Allocate memory for private key
     size_t priv_size = BR_EC_KBUF_PRIV_MAX_SIZE;
     _private_key_buf = (unsigned char *)malloc(priv_size);
     if (_private_key_buf == nullptr) {
         return false;
     }
     
     // Allocate memory for public key
     size_t pub_size = BR_EC_KBUF_PUB_MAX_SIZE;
     _public_key_buf = (unsigned char *)malloc(pub_size);
     if (_public_key_buf == nullptr) {
         free(_private_key_buf);
         _private_key_buf = nullptr;
         return false;
     }
     
     // Generate the key pair
     const br_prng_class **rng = (const br_prng_class **)&_rng_ctx;
     _private_key.curve = _curve;
     _private_key_len = br_ec_keygen(rng, _ec_impl, &_private_key, _private_key_buf, _curve);
     
     if (_private_key_len == 0) {
         cleanupKeys();
         return false;
     }
     
     // Compute public key
     _public_key.curve = _curve;
     _public_key_len = br_ec_compute_pub(_ec_impl, &_public_key, _public_key_buf, &_private_key);
     
     if (_public_key_len == 0) {
         cleanupKeys();
         return false;
     }
     
     _has_keys = true;
     return true;
 }
 
 bool PicoEC::loadPrivateKey(const uint8_t* privateKey, size_t keyLength) {
     // Clean up existing keys
     cleanupKeys();
     
     // Allocate memory for private key
     _private_key_buf = (unsigned char *)malloc(keyLength);
     if (_private_key_buf == nullptr) {
         return false;
     }
     
     // Copy the private key
     memcpy(_private_key_buf, privateKey, keyLength);
     _private_key.curve = _curve;
     _private_key.x = _private_key_buf;
     _private_key.xlen = keyLength;
     _private_key_len = keyLength;
     
     // If we have a private key but no public key, compute public key
     size_t pub_size = BR_EC_KBUF_PUB_MAX_SIZE;
     _public_key_buf = (unsigned char *)malloc(pub_size);
     if (_public_key_buf == nullptr) {
         cleanupKeys();
         return false;
     }
     
     _public_key.curve = _curve;
     _public_key_len = br_ec_compute_pub(_ec_impl, &_public_key, _public_key_buf, &_private_key);
     
     if (_public_key_len == 0) {
         cleanupKeys();
         return false;
     }
     
     _has_keys = true;
     return true;
 }
 
 bool PicoEC::loadPublicKey(const uint8_t* publicKey, size_t keyLength) {
     // For public key only, we keep the old private key (if any)
     if (_public_key_buf != nullptr) {
         free(_public_key_buf);
         _public_key_buf = nullptr;
     }
     
     // Allocate memory for public key
     _public_key_buf = (unsigned char *)malloc(keyLength);
     if (_public_key_buf == nullptr) {
         return false;
     }
     
     // Copy the public key
     memcpy(_public_key_buf, publicKey, keyLength);
     _public_key.curve = _curve;
     _public_key.q = _public_key_buf;
     _public_key.qlen = keyLength;
     _public_key_len = keyLength;
     
     _has_keys = true;
     return true;
 }
 
 size_t PicoEC::getPrivateKey(uint8_t* buffer, size_t maxLen) const {
     if (!_has_keys || _private_key_buf == nullptr || _private_key_len == 0) {
         return 0;
     }
     
     if (maxLen < _private_key_len) {
         return 0;
     }
     
     memcpy(buffer, _private_key_buf, _private_key_len);
     return _private_key_len;
 }
 
 size_t PicoEC::getPublicKey(uint8_t* buffer, size_t maxLen) const {
     if (!_has_keys || _public_key_buf == nullptr || _public_key_len == 0) {
         return 0;
     }
     
     if (maxLen < _public_key_len) {
         return 0;
     }
     
     memcpy(buffer, _public_key_buf, _public_key_len);
     return _public_key_len;
 }
 
 size_t PicoEC::sign(const uint8_t* message, size_t messageLen, 
                     uint8_t* signature, size_t maxSignatureLen,
                     PicoECSignatureFormat format,
                     bool isHash) {
     if (!_has_keys || _private_key_buf == nullptr) {
         return 0;
     }
     
     // If message is not a pre-computed hash, hash it with SHA-256
     unsigned char hash[32];
     const void* hash_data;
     
     if (!isHash) {
         br_sha256_context sha_ctx;
         br_sha256_init(&sha_ctx);
         br_sha256_update(&sha_ctx, message, messageLen);
         br_sha256_out(&sha_ctx, hash);
         hash_data = hash;
     } else {
         hash_data = message;
     }
     
     // Sign the message/hash
     size_t sig_len;
     if (format == EC_SIGNATURE_ASN1) {
         sig_len = _sign_impl_asn1(_ec_impl, sha256_impl, hash_data, &_private_key, signature);
     } else {
         sig_len = _sign_impl_raw(_ec_impl, sha256_impl, hash_data, &_private_key, signature);
     }
     
     return sig_len;
 }
 
 bool PicoEC::verify(const uint8_t* message, size_t messageLen,
                     const uint8_t* signature, size_t signatureLen,
                     PicoECSignatureFormat format,
                     bool isHash) {
     if (!_has_keys || _public_key_buf == nullptr) {
         return false;
     }
     
     // If message is not a pre-computed hash, hash it with SHA-256
     unsigned char hash[32];
     const void* hash_data;
     size_t hash_len;
     
     if (!isHash) {
         br_sha256_context sha_ctx;
         br_sha256_init(&sha_ctx);
         br_sha256_update(&sha_ctx, message, messageLen);
         br_sha256_out(&sha_ctx, hash);
         hash_data = hash;
         hash_len = sizeof(hash);
     } else {
         hash_data = message;
         hash_len = messageLen;
     }
     
     // Verify the signature
     uint32_t result;
     if (format == EC_SIGNATURE_ASN1) {
         result = _verify_impl_asn1(_ec_impl, hash_data, hash_len, 
                                   &_public_key, signature, signatureLen);
     } else {
         result = _verify_impl_raw(_ec_impl, hash_data, hash_len, 
                                  &_public_key, signature, signatureLen);
     }
     
     return result == 1;
 }
 
 size_t PicoEC::computeSharedSecret(const uint8_t* peerPublicKey, size_t peerKeyLen,
                                   uint8_t* sharedSecret, size_t maxSecretLen) {
     if (!_has_keys || _private_key_buf == nullptr) {
         return 0;
     }
     
     // Create temporary public key for peer
     br_ec_public_key peer_key;
     peer_key.curve = _curve;
     peer_key.q = (unsigned char*)peerPublicKey;
     peer_key.qlen = peerKeyLen;
     
     // Ensure buffer is big enough for curve point
     if (maxSecretLen < getCurveMaxSize()) {
         return 0;
     }
     
     // For ECDH, we need to:
     // 1. Extract x-coordinate from the result of multiplying peer's public key by our private key
     size_t xlen;
     size_t xoff = _ec_impl->xoff(_curve, &xlen);
     
     // Copy peer's public key to temporary buffer
     memcpy(_tmp_buffer, peerPublicKey, peerKeyLen);
     
     // Multiply our private key with peer's public key
     uint32_t result = _ec_impl->mul(_tmp_buffer, peerKeyLen, 
                                     _private_key.x, _private_key.xlen, _curve);
     
     if (result != 1) {
         return 0;
     }
     
     // Extract x-coordinate for the shared secret
     memcpy(sharedSecret, _tmp_buffer + xoff, xlen);
     return xlen;
 }
 
 void PicoEC::addEntropy(const uint8_t* seed, size_t seedLen) {
     // Add external entropy to the RNG
     br_hmac_drbg_update(&_rng_ctx, seed, seedLen);
 }
 
 size_t PicoEC::getMaxSignatureLength(PicoECSignatureFormat format) const {
     size_t raw_len = getCurveMaxSize() * 2;
     
     // ASN.1 format can add up to 9 bytes of overhead
     if (format == EC_SIGNATURE_ASN1) {
         return raw_len + 9;
     }
     
     return raw_len;
 }
 
 bool PicoEC::hasKeys() const {
     return _has_keys;
 }
 
 PicoECCurve PicoEC::getCurve() const {
     return _curve;
 }
 
 bool PicoEC::setCurve(PicoECCurve curve) {
     // Don't do anything if curve is the same
     if (_curve == curve) {
         return true;
     }
     
     // Check if the curve is supported
     uint32_t supported = _ec_impl->supported_curves;
     if ((supported & (1U << curve)) == 0) {
         return false;
     }
     
     // Clean up and switch to new curve
     cleanupKeys();
     _curve = curve;
     
     // Re-initialize with new curve
     initializeImplementation();
     return true;
 }
 
 bool PicoEC::convertRawToAsn1(uint8_t* signature, size_t* signatureLen) {
     size_t new_len = br_ecdsa_raw_to_asn1(signature, *signatureLen);
     if (new_len == 0) {
         return false;
     }
     
     *signatureLen = new_len;
     return true;
 }
 
 bool PicoEC::convertAsn1ToRaw(uint8_t* signature, size_t* signatureLen) {
     size_t new_len = br_ecdsa_asn1_to_raw(signature, *signatureLen);
     if (new_len == 0) {
         return false;
     }
     
     *signatureLen = new_len;
     return true;
 }