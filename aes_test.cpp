/* 
    Program for Testing AES (CBC) Encryption using MbedTLS library (by ARMmbed)
    (Library url: https://github.com/ARMmbed/mbedtls)

    by CC Dharmani, Jan 2021
    Tested on: Raspberry Pi Pico (PlatformIO, Arduino-Mbed)
 */

#include <Arduino.h>
#include "mbed.h"
#include "md.h"
#include "aes.h"

#define AES_128   128
#define AES_192   192
#define AES_256   256

//AES Encryption Key (given here only as an example)
uint8_t aes_key[32] = {0x30, 0x30, 0x30, 0x30, 
                       0x30, 0x30, 0x30, 0x30, 
                       0x30, 0x30, 0x30, 0x30, 
                       0x30, 0x30, 0x30, 0x30,
                       0x30, 0x30, 0x30, 0x30, 
                       0x30, 0x30, 0x30, 0x30, 
                       0x30, 0x30, 0x30, 0x30, 
                       0x30, 0x30, 0x30, 0x30};

//General initialization vector (given here only as an example)
uint8_t aes_iv[16] = {0x01, 0x01, 0x01, 0x01, 
                      0x02, 0x02, 0x02, 0x02, 
                      0x03, 0x03, 0x03, 0x03, 
                      0x04, 0x04, 0x04, 0x04};

uint8_t iv_copy[16]; //iv gets overwritten, so maintain local copy

void setup() {
  Serial.begin(115200);
  while(!Serial);
  delay(1000);

  for(int i=0; i<16; i++) iv_copy[i] = aes_iv[i];
  Serial.println("\nTesting MbedTLS lib on Raspberry Pi Pico (mbed-arduino)");
}

const char plainText[] = "AES_Test_3 - Hello! Testing AES Encryption here";
byte enc_iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
mbedtls_aes_context aes_encrypt, aes_decrypt; //encryption objects declaration

void loop() {
  uint32_t t1, t2;
  Serial.println("\nINPUT: " + (String)plainText);
  // prepare data, generate according to AES algorithm

  int dataLength = sizeof(plainText);
  if((dataLength % 16) != 0) dataLength += 16 - (dataLength % 16);  //keep the length multiple of 16 for encryption/ decryption

  mbedtls_aes_setkey_enc( &aes_encrypt, aes_key, AES_128); // size of key must be given as 128, 192 or 256 bit
  unsigned char* encrypted = new unsigned char[dataLength];
  t1 = micros();
  mbedtls_aes_crypt_cbc(&aes_encrypt, MBEDTLS_AES_ENCRYPT, dataLength, aes_iv, (const unsigned char*)plainText, encrypted); //Encryption
  t2 = micros();
  
  Serial.print("Cipher Text: "); 
  for (int i=0; i<dataLength;i++) {
        Serial.print((char)encrypted[i], HEX);
  }
  Serial.print("\nEncryption Time (us): "); Serial.println(t2-t1);

  for(int i=0; i<16; i++) aes_iv[i] = iv_copy[i];   //restore iv
 
  mbedtls_aes_setkey_dec(&aes_decrypt, aes_key, AES_128);
  unsigned char* decrypted = new unsigned char[sizeof(plainText)];
  t1 = micros();
  mbedtls_aes_crypt_cbc(&aes_decrypt, MBEDTLS_AES_DECRYPT, dataLength, aes_iv, encrypted, decrypted); //Decryption
  t2 = micros();
  
  Serial.print("Plain Text: "); Serial.println((char*)decrypted);
  Serial.print("Decryption Time (us): "); Serial.println(t2-t1);

  if (String((char*)decrypted).equals(plainText)) Serial.println("SUCCESS");
  else Serial.println("FAILURE");

  delete [] encrypted;
  delete [] decrypted;

  for(int i=0; i<16; i++) aes_iv[i] = iv_copy[i];   //restore aes_iv

  while(!Serial.available());   //wait till a serial receive 
  Serial.read();                //flush the received character
}
