/**
 * ECDHKeyExchange example
 * 
 * This example demonstrates Elliptic Curve Diffie-Hellman (ECDH) key exchange
 * using the PicoEC library. ECDH allows two parties to establish a shared
 * secret over an insecure channel.
 * 
 * For Raspberry Pi Pico W using Arduino-Pico core
 */

 #include <Arduino.h>
 #include <picoEC.h>
 
 // Forward declaration of utility function
 void printHex(const uint8_t* data, size_t len);
 
 // Create two EC instances to simulate two parties (Alice and Bob)
 PicoEC alice(EC_SECP256R1);
 PicoEC bob(EC_SECP256R1);
 
 void setup() {
   // Initialize serial communication
   Serial.begin(115200);
   while (!Serial) delay(10);
   
   Serial.println("\n\n==================================================");
   Serial.println("PicoEC Library - ECDH Key Exchange Example");
   Serial.println("==================================================\n");
   
   // Add entropy to both instances
   uint8_t entropy[32];
   Serial.println("Collecting entropy...");
   for (int i = 0; i < 32; i++) {
     entropy[i] = analogRead(A0 + (i % 4)) & 0xFF;
     entropy[i] ^= micros() & 0xFF;
   }
   alice.addEntropy(entropy, sizeof(entropy));
   
   // Different entropy for Bob
   delay(50);
   for (int i = 0; i < 32; i++) {
     entropy[i] = analogRead(A0 + (i % 4)) & 0xFF;
     entropy[i] ^= micros() & 0xFF;
   }
   bob.addEntropy(entropy, sizeof(entropy));
   
   // Generate key pairs for both parties
   Serial.println("Generating Alice's key pair...");
   if (!alice.generateKeyPair()) {
     Serial.println("ERROR: Failed to generate Alice's key pair!");
     return;
   }
   
   Serial.println("Generating Bob's key pair...");
   if (!bob.generateKeyPair()) {
     Serial.println("ERROR: Failed to generate Bob's key pair!");
     return;
   }
   
   // Extract public keys
   uint8_t alicePublicKey[128];
   uint8_t bobPublicKey[128];
   
   size_t alicePublicKeyLen = alice.getPublicKey(alicePublicKey, sizeof(alicePublicKey));
   size_t bobPublicKeyLen = bob.getPublicKey(bobPublicKey, sizeof(bobPublicKey));
   
   if (alicePublicKeyLen == 0 || bobPublicKeyLen == 0) {
     Serial.println("ERROR: Failed to extract public keys!");
     return;
   }
   
   Serial.print("Alice's public key (");
   Serial.print(alicePublicKeyLen);
   Serial.println(" bytes):");
   printHex(alicePublicKey, alicePublicKeyLen);
   
   Serial.print("\nBob's public key (");
   Serial.print(bobPublicKeyLen);
   Serial.println(" bytes):");
   printHex(bobPublicKey, bobPublicKeyLen);
   
   // Exchange public keys (in a real scenario, this would happen over a network)
   
   // Alice computes shared secret using Bob's public key
   uint8_t aliceSharedSecret[64];
   size_t aliceSecretLen = alice.computeSharedSecret(
     bobPublicKey, bobPublicKeyLen,
     aliceSharedSecret, sizeof(aliceSharedSecret)
   );
   
   if (aliceSecretLen == 0) {
     Serial.println("\nERROR: Alice failed to compute shared secret!");
     return;
   }
   
   // Bob computes shared secret using Alice's public key
   uint8_t bobSharedSecret[64];
   size_t bobSecretLen = bob.computeSharedSecret(
     alicePublicKey, alicePublicKeyLen,
     bobSharedSecret, sizeof(bobSharedSecret)
   );
   
   if (bobSecretLen == 0) {
     Serial.println("\nERROR: Bob failed to compute shared secret!");
     return;
   }
   
   // Display the shared secrets (they should be identical)
   Serial.print("\nAlice's computed shared secret (");
   Serial.print(aliceSecretLen);
   Serial.println(" bytes):");
   printHex(aliceSharedSecret, aliceSecretLen);
   
   Serial.print("\nBob's computed shared secret (");
   Serial.print(bobSecretLen);
   Serial.println(" bytes):");
   printHex(bobSharedSecret, bobSecretLen);
   
   // Verify that both shared secrets are identical
   bool secretsMatch = (aliceSecretLen == bobSecretLen);
   if (secretsMatch) {
     for (size_t i = 0; i < aliceSecretLen; i++) {
       if (aliceSharedSecret[i] != bobSharedSecret[i]) {
         secretsMatch = false;
         break;
       }
     }
   }
   
   Serial.println("\nShared secrets " + String(secretsMatch ? "MATCH" : "DO NOT MATCH"));
   
   if (secretsMatch) {
     Serial.println("\nSuccessful ECDH key exchange! Both parties now have the same shared secret.");
     Serial.println("This shared secret can be used as a key for symmetric encryption.");
   } else {
     Serial.println("\nERROR: ECDH key exchange failed. Shared secrets don't match.");
   }
   
   // Example of using the shared secret as an AES key (conceptual)
   Serial.println("\nExample use: The shared secret can now be used as a key for AES encryption.");
   Serial.println("This allows secure communication using symmetric encryption with a key");
   Serial.println("that was never directly transmitted over the network.");
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
