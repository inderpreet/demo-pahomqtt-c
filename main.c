
#include <stdio.h>
#include "MQTTClient.h"
#include <stdlib.h>
#include <string.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/timing.h"
#include "mbedtls/aes.h"


#define ADDRESS     "tcp://192.168.2.75:1883"
#define CLIENTID    "ExampleClientSub"
#define TOPIC       "MQTT_TEST"
#define PAYLOAD     "Hello World!"
#define QOS         1
#define TIMEOUT     10000L

#define AES_128   128
#define AES_192   192
#define AES_256   256


/**
 * @section MQTT Client Demo Section
 * **************************************************************************
 */
volatile MQTTClient_deliveryToken deliveredtoken;


void delivered(void *context, MQTTClient_deliveryToken dt)
{
    printf("Message with token value %d delivery confirmed\n", dt);
    deliveredtoken = dt;
}


int msgarrvd(void *context, char *topicName, int topicLen, MQTTClient_message *message)
{
    int i;
    char* payloadptr;
    printf("Message arrived\n");
    printf("     topic: %s\n", topicName);
    printf("   message: ");
    payloadptr = message->payload;
    for(i=0; i<message->payloadlen; i++)
    {
        putchar(*payloadptr++);
    }
    putchar('\n');
    MQTTClient_freeMessage(&message);
    MQTTClient_free(topicName);
    return 1;
}


void connlost(void *context, char *cause)
{
    printf("\nConnection lost\n");
    printf("     cause: %s\n", cause);
}

void onConnected(void)
{
    printf("\nConnected!");
}

void onFailedConnection(void)
{
    printf("\nConnection Failed");
}

int mqtt_demo1(void)
{
    MQTTClient client;
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    int rc;
    int ch;

    rc = MQTTClient_create(&client, ADDRESS, CLIENTID, MQTTCLIENT_PERSISTENCE_NONE, NULL);
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;
    
    conn_opts.username = "manager";
    conn_opts.password = "SuperUser$123";

    rc = MQTTClient_setCallbacks(client, NULL, connlost, msgarrvd, delivered);

    if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS)
    {
        printf("Failed to connect, return code %d\n", rc);
        exit(EXIT_FAILURE);
    }
    printf("Subscribing to topic %s\nfor client %s using QoS%d\n\n"
           "Press Q<Enter> to quit\n\n", TOPIC, CLIENTID, QOS);
    MQTTClient_subscribe(client, TOPIC, QOS);
    do
    {
        ch = getchar();
    } while(ch!='Q' && ch != 'q');
    MQTTClient_disconnect(client, 10000);
    MQTTClient_destroy(&client);
    return rc;
}


/**
 * @section MbedTLS Enxryption Demo Section
 * **************************************************************************
 */

int aes_demo(void)
{
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

    const char plainText[53] = "AES Test: Testing AES encryption with MbedTLS Lbrary";
    int len=53;

    unsigned char buf1[53], buf2[53];
    // unsigned char *encrypted, *decrypted;


    uint8_t enc_iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    mbedtls_aes_context aes_encrypt, aes_decrypt;

    printf("\nTesting with : %s", plainText);

    if((len % 16) != 0) {
        len += 16 - (len % 16);
    }   //keep the length multiple of 16 for encryption/ decryption


    for(int i=0; i<16; i++) iv_copy[i] = aes_iv[i];

    mbedtls_aes_setkey_enc( &aes_encrypt, aes_key, AES_128); // size of key must be given as 128, 192 or 256 bit
    mbedtls_aes_crypt_cbc(&aes_encrypt, MBEDTLS_AES_ENCRYPT, len, aes_iv, (const unsigned char*)plainText, buf1); //Encryption

    for(int i=0; i<16; i++) aes_iv[i] = iv_copy[i];   //restore iv

    mbedtls_aes_setkey_dec(&aes_decrypt, aes_key, AES_128);
    mbedtls_aes_crypt_cbc(&aes_decrypt, MBEDTLS_AES_DECRYPT, len, aes_iv, buf1, buf2); //Decryption
    
    printf("\nEncrypted: %s", buf1);
    printf("\nDecrypted: %s\n", buf2);
  
    return 0;
}


int main() {
    printf("Hello world\n");
    aes_demo();
    // mqtt_demo1();
 
    return 0;
}
