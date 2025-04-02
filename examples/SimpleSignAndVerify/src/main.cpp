/**
 * SimpleSignAndVerify example
 * 
 * This example demonstrates basic usage of the PicoEC library:
 * - Generating EC key pairs
 * - Signing messages
 * - Verifying signatures
 * 
 * For Raspberry Pi Pico W using Arduino-Pico core
 */

 #include <Arduino.h>
 #include <picoEC.h>
 
 // Forward declaration of utility function
 void printHex(const uint8_t* data, size_t len);
 
 // Create EC instance with NIST P-256 curve
 PicoEC ec(EC_SECP256R1);
 
 void setup() {
   // Initialize serial communication
   Serial.begin(115200);
   while (!Serial) delay(10);
   
   Serial.println("\n\n================================================");
   Serial.println("PicoEC Library - Simple Sign and Verify Example");
   Serial.println("================================================\n");
   
   // Add some entropy by reading analog pins
   uint8_t entropy[32];
   Serial.println("Collecting entropy...");
   for (int i = 0; i < 32; i++) {
     entropy[i] = analogRead(A0 + (i % 4)) & 0xFF;
   }
   ec.addEntropy(entropy, sizeof(entropy));
   
   // Generate a new key pair
   Serial.println("Generating a new EC key pair...");
   unsigned long startTime = millis();
   bool result = ec.generateKeyPair();
   unsigned long duration = millis() - startTime;
   
   if (!result) {
     Serial.println("ERROR: Key generation failed!");
     return;
   }
   
   Serial.print("Key generation took ");
   Serial.print(duration);
   Serial.println(" ms");
   
   // Get and print the keys
   uint8_t privateKey[64];
   uint8_t publicKey[128];
   size_t privateKeyLen = ec.getPrivateKey(privateKey, sizeof(privateKey));
   size_t publicKeyLen = ec.getPublicKey(publicKey, sizeof(publicKey));
   
   Serial.print("Private key (");
   Serial.print(privateKeyLen);
   Serial.println(" bytes):");
   printHex(privateKey, privateKeyLen);
   
   Serial.print("Public key (");
   Serial.print(publicKeyLen);
   Serial.println(" bytes):");
   printHex(publicKey, publicKeyLen);
   Serial.println();
   
   // Try signing a message
   const char* message = "Hello, Raspberry Pi Pico with Elliptic Curves!";
   Serial.print("Message to sign: ");
   Serial.println(message);
   
   // Buffer for signature
   uint8_t signature[128];
   
   // Sign the message (ASN.1 format)
   size_t signatureLen = ec.sign((const uint8_t*)message, strlen(message), 
                                signature, sizeof(signature), EC_SIGNATURE_ASN1);
   
   if (signatureLen > 0) {
     Serial.print("Signature (ASN.1 format, ");
     Serial.print(signatureLen);
     Serial.println(" bytes):");
     printHex(signature, signatureLen);
   } else {
     Serial.println("ERROR: Signing failed!");
     return;
   }
   
   // Verify the signature
   bool verified = ec.verify((const uint8_t*)message, strlen(message), 
                           signature, signatureLen, EC_SIGNATURE_ASN1);
   
   Serial.println("\nVerification result: " + String(verified ? "SUCCESS" : "FAILED"));
   
   // Try with a tampered message
   const char* tamperedMessage = "Hello, Raspberry Pi Pico with TAMPERED message!";
   Serial.print("\nTampered message: ");
   Serial.println(tamperedMessage);
   
   // Verify again with tampered message - should fail
   verified = ec.verify((const uint8_t*)tamperedMessage, strlen(tamperedMessage), 
                      signature, signatureLen, EC_SIGNATURE_ASN1);
   
   Serial.println("Verification with tampered message: " + 
                 String(verified ? "INCORRECT SUCCESS!" : "CORRECTLY FAILED"));
   
   // Generate RAW format signature
   Serial.println("\nGenerating RAW format signature...");
   signatureLen = ec.sign((const uint8_t*)message, strlen(message), 
                         signature, sizeof(signature), EC_SIGNATURE_RAW);
   
   if (signatureLen > 0) {
     Serial.print("Signature (RAW format, ");
     Serial.print(signatureLen);
     Serial.println(" bytes):");
     printHex(signature, signatureLen);
   } else {
     Serial.println("ERROR: RAW format signing failed!");
     return;
   }
   
   // Verify the RAW signature
   verified = ec.verify((const uint8_t*)message, strlen(message), 
                      signature, signatureLen, EC_SIGNATURE_RAW);
   
   Serial.println("\nRAW format verification result: " + 
                 String(verified ? "SUCCESS" : "FAILED"));
   
   Serial.println("\nAll operations completed successfully!");
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