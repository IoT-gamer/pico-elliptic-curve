# Pico Elliptic Curve Library for Raspberry Pi Pico

A lightweight Elliptic Curve Cryptography (ECC) library for Raspberry Pi Pico W using the Arduino-Pico core which includes BearSSL.

## Features

- **EC Key Generation** - Generate EC key pairs directly on your microcontroller
- **ECDSA Signatures** - Sign and verify messages using ECDSA with various curves
- **ECDH Key Exchange** - Perform secure key exchange using Elliptic Curve Diffie-Hellman
- **Multiple Curve Support** - Use NIST P-256, P-384, P-521, or Curve25519
- **ASN.1 and Raw Formats** - Support for both standard signature formats
- **Simple API** - Easy-to-use functions with clear documentation
- **Low Resource Usage** - Optimized for microcontrollers with limited resources

## Installation

### PlatformIO

Edit your project's `platformio.ini`:

```ini
[env:rpipicow]
platform = https://github.com/maxgerhardt/platform-raspberrypi.git
board = rpipicow
framework = arduino
board_build.core = earlephilhower
board_build.filesystem_size = 0.5m
lib_deps =
    pico-elliptic-curve

; Or if you want to use the latest version from GitHub
; lib_deps =
;    https://github.com/IoT-gamer/pico-elliptic-curve
```

### Arduino IDE

1. Create a folder named PicoEC in your Arduino libraries folder
2. Copy the `picoEC.h` and `picoEC.cpp` files into this folder
3. Restart the Arduino IDE

## Hardware Compatibility

This library has been tested with:
- Raspberry Pi Pico W with Arduino-Pico core

It should work with any board that:
- Supports the Arduino-Pico core (which includes BearSSL)
- Has sufficient RAM for EC operations

## Curve Recommendations

- **EC_SECP256R1 (NIST P-256)**: Good balance of security and performance for most applications
- **EC_SECP384R1 (NIST P-384)**: Higher security, but more resource-intensive
- **EC_SECP521R1 (NIST P-521)**: Very high security, but slow on Pico W
- **EC_CURVE25519**: Excellent for ECDH key exchange, but not for ECDSA signatures

## Examples

The library includes the following examples:

- **SimpleSignAndVerify**: Basic example of EC key generation and ECDSA signatures
- **ECDHKeyExchange**: Demonstrates secure key exchange between two parties
- **Curve25519Example**: Shows the performance benefits of Curve25519 for ECDH

## API Reference

### Constructor

```cpp
PicoEC(PicoECCurve curve = EC_SECP256R1);
```

Creates a new PicoEC instance with the specified curve.

### Key Management

```cpp
bool generateKeyPair(bool collectEntropy = true);
```

Generates a new EC key pair. If `collectEntropy` is true, additional entropy is automatically collected from analog pins.

```cpp
bool loadPrivateKey(const uint8_t* privateKey, size_t keyLength);
```

Loads a private key from a buffer.

```cpp
bool loadPublicKey(const uint8_t* publicKey, size_t keyLength);
```

Loads a public key from a buffer.

```cpp
size_t getPrivateKey(uint8_t* buffer, size_t maxLen) const;
```

Copies the private key to a buffer and returns its length.

```cpp
size_t getPublicKey(uint8_t* buffer, size_t maxLen) const;
```

Copies the public key to a buffer and returns its length.

### Digital Signatures

```cpp
size_t sign(const uint8_t* message, size_t messageLen, 
           uint8_t* signature, size_t maxSignatureLen,
           PicoECSignatureFormat format = EC_SIGNATURE_ASN1,
           bool isHash = false);
```

Signs a message (or pre-computed hash) and returns the signature length.

```cpp
bool verify(const uint8_t* message, size_t messageLen,
           const uint8_t* signature, size_t signatureLen,
           PicoECSignatureFormat format = EC_SIGNATURE_ASN1,
           bool isHash = false);
```

Verifies a signature against a message (or pre-computed hash).

### Key Exchange (ECDH)

```cpp
size_t computeSharedSecret(const uint8_t* peerPublicKey, size_t peerKeyLen,
                          uint8_t* sharedSecret, size_t maxSecretLen);
```

Computes a shared secret with another party's public key using ECDH.

### Utility Functions

```cpp
void addEntropy(const uint8_t* seed, size_t seedLen);
```

Adds additional entropy to the random number generator.

```cpp
size_t getMaxSignatureLength(PicoECSignatureFormat format) const;
```

Returns the maximum signature length for the current curve and format.

```cpp
bool hasKeys() const;
```

Returns true if keys have been generated or loaded.

```cpp
PicoECCurve getCurve() const;
```

Returns the current curve identifier.

```cpp
bool setCurve(PicoECCurve curve);
```

Changes the curve used by the library.

```cpp
static bool convertRawToAsn1(uint8_t* signature, size_t* signatureLen);
```

Converts a signature from raw to ASN.1 format (in-place).

```cpp
static bool convertAsn1ToRaw(uint8_t* signature, size_t* signatureLen);
```

Converts a signature from ASN.1 to raw format (in-place).

## Security Considerations

- **Entropy Quality:** EC key generation requires good entropy. The library collects entropy from analog inputs, but consider adding additional entropy sources for critical applications.
- **Curve Selection:** Use EC_SECP256R1 (NIST P-256) as a good compromise for most applications.
- **Storage:** This library does not handle persistent storage of keys. For production use, implement secure key storage.
- **Side-Channel Attacks:** While BearSSL implements constant-time operations to mitigate side-channel attacks, no guarantees are provided against hardware-level attacks.

## Entropy Guide

For critical applications, consider improving the entropy for key generation:

```cpp
// Create additional entropy from various sources
uint8_t extraEntropy[32];

// Use floating analog pins
for (int i = 0; i < 8; i++) {
  extraEntropy[i] = analogRead(A0 + i) & 0xFF;
}

// Mix in timing data
for (int i = 8; i < 16; i++) {
  extraEntropy[i] = (micros() >> ((i-8)*4)) & 0xFF;
}

// Use WiFi if available (Pico W)
#ifdef ARDUINO_ARCH_RP2040
  #include <WiFi.h>
  if (WiFi.status() == WL_CONNECTED) {
    extraEntropy[16] = WiFi.RSSI() & 0xFF;
  }
#endif

// Add the entropy before generating keys
PicoEC ec(EC_SECP256R1);
ec.addEntropy(extraEntropy, sizeof(extraEntropy));
ec.generateKeyPair(false);  // Don't automatically collect more entropy
```

## Comparison with RSA

Elliptic Curve Cryptography offers several advantages over RSA:

1. **Smaller Key Sizes**: EC provides equivalent security to RSA with much smaller keys
   - 256-bit EC ≈ 3072-bit RSA
   - 384-bit EC ≈ 7680-bit RSA

2. **Better Performance**: EC operations are generally faster than RSA on constrained devices
   - Key generation is significantly faster
   - Signature verification is more efficient

3. **Lower Memory Usage**: EC requires less RAM for both keys and operations

4. **Future-Proof**: EC scales better for higher security levels

This makes EC an excellent choice for IoT and embedded applications where resources are limited.

## License

This library is released under the MIT License. See LICENSE for details.

## Acknowledgments

- Based on [BearSSL](https://bearssl.org/) by Thomas Pornin
- Developed using [Arduino-Pico core](https://github.com/earlephilhower/arduino-pico) by Earle F. Philhower, III
- Inspired by RSA implementation from [PicoRSA library](https://github.com/IoT-gamer/pico-rsa)
