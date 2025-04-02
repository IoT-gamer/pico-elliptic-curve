/**
 * Curve25519Example
 * 
 * This example demonstrates the use of Curve25519 for ECDH key exchange,
 * which is particularly optimized for this purpose.
 * 
 * For Raspberry Pi Pico W using Arduino-Pico core
 */

 #include <Arduino.h>
 #include <picoEC.h>
 
 // Forward declaration of utility function
 void printHex(const uint8_t* data, size_t len);
 
 // For performance comparison
 unsigned long nistp256Time = 0;
 unsigned long curve25519Time = 0;
 
 void setup() {
   // Initialize serial communication
   Serial.begin(115200);
   while (!Serial) delay(10);
   
   Serial.println("\n\n========================================");
   Serial.println("PicoEC Library - Curve25519 Example");
   Serial.println("========================================\n");
   
   // Collect some entropy
   uint8_t entropy[32];
   for (int i = 0; i < 32; i++) {
     entropy[i] = analogRead(A0 + (i % 4)) ^ (micros() & 0xFF);
   }
   
   // First demonstrate ECDH with NIST P-256 for comparison
   Serial.println("Part 1: ECDH with NIST P-256 (for comparison)");
   Serial.println("---------------------------------------------");
   
   // Create two EC instances with NIST P-256 curve
   PicoEC alice(EC_SECP256R1);
   PicoEC bob(EC_SECP256R1);
   
   // Add entropy
   alice.addEntropy(entropy, sizeof(entropy));
   bob.addEntropy(entropy, sizeof(entropy));
   
   // Generate key pairs
   Serial.println("Generating NIST P-256 key pairs...");
   unsigned long startTime = millis();
   
   if (!alice.generateKeyPair() || !bob.generateKeyPair()) {
     Serial.println("ERROR: P-256 key generation failed!");
     return;
   }
   
   nistp256Time = millis() - startTime;
   Serial.print("Key generation took ");
   Serial.print(nistp256Time);
   Serial.println(" ms");
   
   // Extract public keys
   uint8_t alicePublicKey[128];
   uint8_t bobPublicKey[128];
   
   size_t alicePublicKeyLen = alice.getPublicKey(alicePublicKey, sizeof(alicePublicKey));
   size_t bobPublicKeyLen = bob.getPublicKey(bobPublicKey, sizeof(bobPublicKey));
   
   // Compute shared secrets
   uint8_t nistp256AliceSecret[64];
   uint8_t nistp256BobSecret[64];
   
   startTime = millis();
   size_t aliceSecretLen = alice.computeSharedSecret(
     bobPublicKey, bobPublicKeyLen,
     nistp256AliceSecret, sizeof(nistp256AliceSecret)
   );
   
   size_t bobSecretLen = bob.computeSharedSecret(
     alicePublicKey, alicePublicKeyLen,
     nistp256BobSecret, sizeof(nistp256BobSecret)
   );
   
   unsigned long nistp256DhTime = millis() - startTime;
   
   Serial.print("P-256 shared secret computation took ");
   Serial.print(nistp256DhTime);
   Serial.println(" ms");
   
   // Verify that shared secrets match
   bool secretsMatch = (aliceSecretLen == bobSecretLen);
   if (secretsMatch) {
     for (size_t i = 0; i < aliceSecretLen; i++) {
       if (nistp256AliceSecret[i] != nistp256BobSecret[i]) {
         secretsMatch = false;
         break;
       }
     }
   }
   
   Serial.println("P-256 ECDH result: " + String(secretsMatch ? "SUCCESS" : "FAILED"));
   
   // Now demonstrate Curve25519 ECDH
   Serial.println("\nPart 2: ECDH with Curve25519");
   Serial.println("----------------------------");
   
   // Create two EC instances with Curve25519
   PicoEC alice25519(EC_CURVE25519);
   PicoEC bob25519(EC_CURVE25519);
   
   // Add entropy
   alice25519.addEntropy(entropy, sizeof(entropy));
   bob25519.addEntropy(entropy, sizeof(entropy));
   
   // Generate key pairs
   Serial.println("Generating Curve25519 key pairs...");
   startTime = millis();
   
   if (!alice25519.generateKeyPair() || !bob25519.generateKeyPair()) {
     Serial.println("ERROR: Curve25519 key generation failed!");
     return;
   }
   
   curve25519Time = millis() - startTime;
   Serial.print("Key generation took ");
   Serial.print(curve25519Time);
   Serial.println(" ms");
   
   // Extract public keys
   uint8_t alice25519PublicKey[32];
   uint8_t bob25519PublicKey[32];
   
   size_t alice25519PubLen = alice25519.getPublicKey(alice25519PublicKey, sizeof(alice25519PublicKey));
   size_t bob25519PubLen = bob25519.getPublicKey(bob25519PublicKey, sizeof(bob25519PublicKey));
   
   // Compute shared secrets
   uint8_t curve25519AliceSecret[32];
   uint8_t curve25519BobSecret[32];
   
   startTime = millis();
   size_t alice25519SecretLen = alice25519.computeSharedSecret(
     bob25519PublicKey, bob25519PubLen,
     curve25519AliceSecret, sizeof(curve25519AliceSecret)
   );
   
   size_t bob25519SecretLen = bob25519.computeSharedSecret(
     alice25519PublicKey, alice25519PubLen,
     curve25519BobSecret, sizeof(curve25519BobSecret)
   );
   
   unsigned long curve25519DhTime = millis() - startTime;
   
   Serial.print("Curve25519 shared secret computation took ");
   Serial.print(curve25519DhTime);
   Serial.println(" ms");
   
   // Verify that shared secrets match
   secretsMatch = (alice25519SecretLen == bob25519SecretLen);
   if (secretsMatch) {
     for (size_t i = 0; i < alice25519SecretLen; i++) {
       if (curve25519AliceSecret[i] != curve25519BobSecret[i]) {
         secretsMatch = false;
         break;
       }
     }
   }
   
   Serial.println("Curve25519 ECDH result: " + String(secretsMatch ? "SUCCESS" : "FAILED"));
   
   // Print shared secret (for demonstration only)
   Serial.println("\nCurve25519 shared secret:");
   printHex(curve25519AliceSecret, alice25519SecretLen);
   
   // Performance comparison
   Serial.println("\nPerformance Comparison");
   Serial.println("----------------------");
   Serial.print("NIST P-256 key generation: ");
   Serial.print(nistp256Time);
   Serial.println(" ms");
   
   Serial.print("Curve25519 key generation: ");
   Serial.print(curve25519Time);
   Serial.println(" ms");
   
   Serial.print("NIST P-256 ECDH computation: ");
   Serial.print(nistp256DhTime);
   Serial.println(" ms");
   
   Serial.print("Curve25519 ECDH computation: ");
   Serial.print(curve25519DhTime);
   Serial.println(" ms");
   
   float keyGenSpeedup = (float)nistp256Time / curve25519Time;
   float dhSpeedup = (float)nistp256DhTime / curve25519DhTime;
   
   Serial.print("\nCurve25519 is ");
   Serial.print(keyGenSpeedup, 1);
   Serial.print("x faster for key generation and ");
   Serial.print(dhSpeedup, 1);
   Serial.println("x faster for ECDH computation.");
   
   Serial.println("\nNote: Curve25519 is specifically optimized for ECDH and offers:");
   Serial.println("- Better performance");
   Serial.println("- Similar security to P-256");
   Serial.println("- More compact keys (32 bytes)");
   Serial.println("- Simpler implementation with fewer side-channel risks");
 }
 
 void loop() {
   // Nothing to do in the loop
   delay(1000);
 }
 
 // Utility function to print bytes in hexadecimal format
 void printHex(const uint8_t* data, size_t len) {
   // Print first 32 bytes (or less if data is shorter)
   size_t printLen = (len > 32) ? 32 : len;
   
   for (size_t i = 0; i < printLen; i++) {
     if (data[i] < 0x10) Serial.print("0");
     Serial.print(data[i], HEX);
     if ((i + 1) % 16 == 0) Serial.println();
     else Serial.print(" ");
   }
   
   if (len > 32) {
     Serial.println("...(truncated)");
   } else if (printLen % 16 != 0) {
     Serial.println();
   }
 }