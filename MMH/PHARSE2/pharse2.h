#ifndef pharse2_H    // Put these two lines at the top of your file.
#define pharse2_H    // (Use a suitable name, usually based on the file name.)

// Place your main header code here.
#include <ChaCha.h>
#include <string.h>
#if defined(ESP8266) || defined(ESP32)
#include <pgmspace.h>
#else
#include <avr/pgmspace.h>
#endif

#define MAX_PLAINTEXT_SIZE  64
#define MAX_CIPHERTEXT_SIZE 64
// Tao random cho intial vector 


#include <SHA512.h>
#define HASH_SIZE 64
#define BLOCK_SIZE 128

struct TestHashVector
{
    const char *name = "";
    const char *data;
    uint8_t hash[HASH_SIZE];
};
struct TestVector
{
    const char *name = "ChaCha20 256-bit";
    byte key[32];
    size_t keySize = 32;
    uint8_t rounds = 20;
    byte plaintext[MAX_PLAINTEXT_SIZE];
    byte ciphertext[MAX_CIPHERTEXT_SIZE];
    byte iv[12] = { 139, 164, 65, 213, 125, 108, 159, 118, 252, 180, 33, 88 };
    byte counter[4] = {109, 110, 111, 112};
    size_t size = 64;
};
TestVector testVector;

ChaCha chacha;

byte buffer[128];

bool testCipher_N(int i,ChaCha *cipher, const struct TestVector *test, size_t inc)
{
    byte output[MAX_CIPHERTEXT_SIZE];
    size_t posn, len;
    //====================CHECK INPUT===========================
    cipher->clear();
    // keysize = length
    // setkey = bool
    if (!cipher->setKey(test->key, test->keySize)) {
        Serial.print("setKey ");
        return false;
    }
    if (!cipher->setIV(test->iv, cipher->ivSize())) {
        Serial.print("setIV ");
        return false;
    }
    if (!cipher->setCounter(test->counter, 4)) {
        Serial.print("setCounter ");
        return false;
    }
    memset(output, 0xBA, sizeof(output));
    //====================ENRYPTION===========================
    if(i == 1)
    {
    for (posn = 0; posn < test->size; posn += inc) {
        len = test->size - posn;
        if (len > inc)
            len = inc;
        cipher->encrypt(output + posn, test->plaintext + posn, len);
    }
    //====================CIPHER TEXT==========================
        Serial.println("ENCRYPT: ");
        Serial.println("PLAIN TEXT: ");
        for(int i = 0; i <sizeof(test->plaintext);++i)
        {
          Serial.printf("%02X", test->plaintext[i]);
        };
        Serial.println();
        Serial.println("CIPHER TEXT: ");
        for(int i = 0; i <sizeof(output);++i)
        {
          Serial.printf("%02X", output[i]);
        };
        Serial.println();
    }else if(i == 2)
    {
    //=========================================================
    cipher->setKey(test->key, test->keySize);
    cipher->setIV(test->iv, cipher->ivSize());
    cipher->setCounter(test->counter, 4);

    //====================DECRYPTION===========================
    // phai thay doi output chu y !!
    Serial.println("DECRYPTION: ");
    Serial.println("CIPHER TEXT: ");
    for(int i = 0; i <sizeof(test->ciphertext);++i)
    {
       Serial.printf("%02X", test->ciphertext[i]);
    };
    Serial.println();
    
    for (posn = 0; posn < test->size; posn += inc) {
        len = test->size - posn;
        if (len > inc)
            len = inc;
        cipher->decrypt(output + posn, test->ciphertext + posn, len);
    }
    //====================PLAIN TEXT==========================
        Serial.println("PLAIN TEXT: ");
        for(int i = 0; i <sizeof(output);++i)
        {
          Serial.printf("%02X", output[i]);
        };
        Serial.println();
        
    //============================================================
    }
    return true;
}
void testCipher(int i,ChaCha *cipher, const struct TestVector *test)
{
    bool ok;

    memcpy_P(&testVector, test, sizeof(TestVector));
    test = &testVector;

    Serial.print(test->name);
    Serial.print(" ... ");

    cipher->setNumRounds(test->rounds);
    
    ok  = testCipher_N(i,cipher, test, test->size);
    
    if (ok)
        {
        Serial.println("Passed");}
    else
        Serial.println("Failed");
}


//===============================================================================
//==================================SHA 512======================================
//===============================================================================
SHA512 sha512;

byte bufferSha[BLOCK_SIZE + 2];

bool testHash_N(Hash *hash, const struct TestHashVector *test, size_t inc)
{
    size_t size = strlen(test->data);
    size_t posn, len;
    uint8_t value[HASH_SIZE];

    hash->reset();
    for (posn = 0; posn < size; posn += inc) 
    {
        len = size - posn;
        if (len > inc)
            len = inc;
        hash->update(test->data + posn, len);
    }
    hash->finalize(value, sizeof(value));
    //=======================HASH VALUE===========================
    Serial.println();
    Serial.println("Hash value: ");
    for(int i = 0; i <sizeof(value);++i)
    {
      Serial.printf("%02X", value[i]); 
    };
    Serial.println();

    return true;
}

void testHash(Hash *hash, const struct TestHashVector *test)
{
    bool ok;

    Serial.print(test->name);
    Serial.print(" ... ");

    ok  = testHash_N(hash, test, strlen(test->data));
    if (ok)
        Serial.println("Passed");
    else
        Serial.println("Failed");
}
#endif // _HEADERFILE_H    // Put this line at the end of your file.
