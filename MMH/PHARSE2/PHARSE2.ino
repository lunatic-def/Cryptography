#include <Crypto.h>
#include "pharse2.h"
#include "ECC.h"
void setup() {
    Serial.begin(9600);
    TestVector p;  
    Serial.println();
    Serial.println("Choose your option:");
    Serial.println("1 = Encrypt & Decrypt");
    Serial.println("2 = SHA512 Hash");
    Serial.println("3 = DIDu = h(IDu||K||Hu)");
    Serial.println("4 = Random number -> Ru = ru*Qu -> Calculate SK = qu*ru*Rs -> Mu = h(Ru,Hu,DIDu,T3)");
    
    while(Serial.available()==0)
    {};
    int j = Serial.parseInt();
    if(j == 1)
    {
      //===============================================================================
      //===================CHACHA20_ENCRYPTION&&DECRYPTION=============================
      //===============================================================================
      Serial.print("Chacha ...");
      Serial.println(sizeof(ChaCha));
      Serial.println();
      //=================KEY================
      Serial.println("Choose your option(1=encrypt, 2=decrypt): ");
      while(Serial.available()==0)
      {};
      int i = Serial.parseInt();
    
      Serial.println("Input 32 bytes ");
      Serial.println("=> Input key");
      while(Serial.available()==0)
      {};
      Serial.readBytes(p.key, 32);
      //=================================
      Serial.println("Max of plain text and cipher text is 64 byte: ");
      Serial.println("Input in Hex format: ");
      String sizecal;
      if(i == 1)
      {
        // Max = 64 
        Serial.println("=> Input plain text for encryption:");
        while(Serial.available()==0)
        {};
        Serial.readBytes(p.plaintext,64);
        // Encrypt i = 1
        testCipher(1,&chacha, &p);
      }
      else if( i == 2)
      {
        Serial.println("=> Input cipher text for decryption: ");
        while(Serial.available()==0)
        {};
        Serial.readBytes(p.ciphertext, MAX_CIPHERTEXT_SIZE);
        // Decrypt i = 2
        testCipher(2,&chacha, &p);
      }
      else
      { 
        Serial.println("Invalid option");
      }
    }else if(j == 2)
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
      TestHashVector p2;
      String test;
      Serial.println("Please input (IDu||K||Hu) in hex format: ");
       while(Serial.available()==0)
      {};
      test = Serial.readString();
      Serial.println();
      Serial.print("DIDu: ");
      p2.data = test.c_str();
      testHash(&sha512, &p2);
      Serial.println();
    }
    else if(j == 4)
    {
      Serial.println("Option 1= ru,Ru ; 2 = SK :");
      while(Serial.available()==0)
      {};
      int e = Serial.parseInt();
      // Random number -> Ru = ru*Qu
      if(e==1)
      {
       testDH(1);
      }
      else if(e == 2)
      {
      testDH(2);
      }
      // Calculate SK = qu*ru*Rs
      
    }
    else 
    {
      Serial.println("Invaid choice!!!");
    }
}
void loop() {
}
