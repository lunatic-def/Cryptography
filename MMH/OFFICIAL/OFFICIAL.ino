#include <Crypto.h>
#include <Curve25519.h>
#include <RNG.h>
#include <string.h>
#include <FS.h>

#include<stdlib.h>
#include<time.h>

#include <string>
#include <ChaCha.h>
#if defined(ESP8266) || defined(ESP32)
#include <pgmspace.h>
#else
#include <avr/pgmspace.h>
#endif

#include <SHA512.h>

#define MAX_PLAINTEXT_SIZE  64
#define MAX_CIPHERTEXT_SIZE 64
#define HASH_SIZE 64
#define BLOCK_SIZE 128
// Tao random cho intial vector 
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

struct TestHashVector
{
    const char *name = "SHA-512: ";
    const char *data;
    uint8_t hash[HASH_SIZE];
};
//===============================================================================
//===================================ECC=========================================
//===============================================================================
void testDH(int j)
{
    static uint8_t alice_k[32];
    static uint8_t alice_f[32];
    static uint8_t bob_pub[32];
    static uint8_t alice_pri[32];
    unsigned long start = micros();
    unsigned long elapsed = micros() - start;
    if (j == 1)
    {
    Serial.println("Diffie-Hellman key exchange:");
    Serial.print("Generate random k/f for User/IOT ... ");
    Serial.flush();
    //unsigned long start = micros();
    Curve25519::dh1(alice_k, alice_f);
    //unsigned long elapsed = micros() - start;
    Serial.print("elapsed ");
    Serial.print(elapsed);
    Serial.println(" us");
    //=======================ALICE PUBLIC AND PRIVATE===========================
    // printf Alice public, private key
    Serial.println();
    Serial.println("User/IOT PublicKey in hex");
    for(int i = 0; i <sizeof(alice_k);++i)
    {
      Serial.printf("%02X", alice_k[i]);
    };
    Serial.println();

    Serial.println("User/IOT PrivateKey in hex");
    for(int i = 0; i <sizeof(alice_f);++i)
    {
      Serial.printf("%02X", alice_f[i]);
    };
    Serial.println();
    }
    else if(j == 2) 
    {
    //==================================================
    //Input
    Serial.println("Input Server Publickey: ");
    while(Serial.available()==0)
    {};
    Serial.readBytes(bob_pub, 32);
    Serial.println("=> Input User Privatekey: ");
    while(Serial.available()==0)
    {};
    Serial.readBytes(alice_pri, 32);
    //Output
    Serial.println("Server public: ");
        for(int i = 0; i <sizeof(bob_pub);++i)
        {
          Serial.printf("%02X", bob_pub[i]);
        };
        Serial.println();

      Serial.println("User private: ");
        for(int i = 0; i <sizeof(alice_pri);++i)
        {
          Serial.printf("%02X", alice_pri[i]);
        };
        Serial.println();
    
    Serial.print("Generate shared secret ... ");
    Serial.flush();
    start = micros();
    Curve25519::dh2(bob_pub, alice_pri);
    elapsed = micros() - start;
    Serial.print("elapsed ");
    Serial.print(elapsed);
    Serial.println(" us");
    Serial.println();

    //=======================SHARE SYMMETRIC KEY===========================

    Serial.println();
    Serial.println("SHARED SYMMETRIC KEY");
    Serial.println(sizeof(bob_pub));
    for(int i = 0; i < sizeof(bob_pub);++i)
    {
      Serial.printf("%02X", bob_pub[i]);
      Serial.print(" "); 
    };
    Serial.println();
  //===============================CHECK KEY=====================================
    /*Serial.print("Check that the shared secrets match ... ");
    if (memcmp(alice_k, bob_k, 32) == 0)
        Serial.println("ok");
    else
        Serial.println("failed");
    }*/
    }
}

//===============================================================================
//===================CHACHA20_ENCRYPTION&&DECRYPTION=============================
//===============================================================================
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

// random hex string for password generator 

void setup()
{
    Serial.begin(9600);
}

void loop()
{
  Serial.println("Choose your option(1=Key generator, 2= Hash, 3 = Encrypt or Dencrypt): ");
    while(Serial.available()==0)
    {};
    int j = Serial.parseInt();
    if(j == 1)
    {
  //==================================KEY GENERATOR===============================
      RNG.begin("Curve25519 1.0");
      Serial.println("Choose your option(1=Key generater, 2=Calculate share key): ");
      while(Serial.available()==0)
      {};
      int e = Serial.parseInt();
      if(e == 1)
      {
        testDH(1);
      }else if(e == 2)
      {
        testDH(2);
      }
    Serial.println("Done! ");
    Serial.println();
    }
    else if(j ==2)
    {
    //===============================================================================
    //======================================SHA512===================================
    //===============================================================================
      Serial.print("HASH ...");
      Serial.println(sizeof(SHA512));
      Serial.println();
      // hash without key :>
      TestHashVector p1;
      Serial.println("Input your value to hash: ");
      while(Serial.available()==0)
      {};
      String c = Serial.readString();
      Serial.println(c);
      p1.data = c.c_str();
      testHash(&sha512, &p1);
      Serial.println();
     } 
    else if(j == 3)
    {
  //===============================================================================
  //===================CHACHA20_ENCRYPTION&&DECRYPTION=============================
  //===============================================================================
      String FORSIZE;
      TestVector p;
      Serial.print("ChaCha20 ...");
      Serial.println(sizeof(ChaCha));
      Serial.println();
      //=================KEY================
      Serial.println("Choose your option(1=encrypt, 2=decrypt): ");
      while(Serial.available()==0)
      {};
      int i = Serial.parseInt();

      // Cho p.key = Bob_k;
      Serial.println("Input 32 bytes ");
      Serial.println("=> Input key");
      while(Serial.available()==0)
      {};
      Serial.readBytes(p.key, 32);
      //=================================
      Serial.println();
      Serial.println("Max of plain text and cipher text is 64 byte: ");
      Serial.println("Input in Hex format: ");
      if(i == 1)
      {
      // Max = 64 
      Serial.println("=> Input plain text for encryption:");
      while(Serial.available()==0)
      {};
      Serial.readBytes(p.plaintext, 64);
      // Encrypt i = 1
      testCipher(1,&chacha, &p);
      }
    
      else if( i == 2)
      {
        Serial.println("=> Input cipher text for decryption: ");
        while(Serial.available()==0)
        {};
        Serial.readBytes(p.ciphertext, 64);
        // Decrypt i = 2
        testCipher(2,&chacha, &p);
      }
    }
    else
    {
        Serial.println("Invalid option");
        Serial.println(); 
    }
}
