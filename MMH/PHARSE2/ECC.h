#ifndef ECC_H    // Put these two lines at the top of your file.
#define ECC_H    // (Use a suitable name, usually based on the file name.)

#include <Crypto.h>
#include <Curve25519.h>
#include <RNG.h>
#include <string.h>
#include <FS.h>

// Nhập public key BOB để alice thực hiện việc tính toán 
// public key = k 
void testDH(int j)
{
  unsigned long start = micros();
  unsigned long elapsed = micros() - start;
  if(j == 1)
  {
    static byte ru[32]; // public
    static byte ru2[32];
    static byte sru[32]; // secret
    static byte Qu[32]; // public key of user
    //static uint8_t Ru[32]; // random point
    

    Serial.print("Generate random value for User/IOT ... ");
    Serial.flush();   
    Curve25519::dh1(ru, sru);
    Serial.print("elapsed ");
    Serial.print(elapsed);
    Serial.println(" us");
    //=======================ALICE PUBLIC AND PRIVATE===========================
    // printf Alice public, private key
    Serial.println();
    Serial.println("Random value ru <> Z*p: ");
    for(int i = 0; i <sizeof(ru);++i)
    {
      Serial.printf("%02X", ru[i]);
    };
    Serial.println();
    //==================================================
    //Input
    Serial.println("=> Input User Public key Qu: ");
    while(Serial.available()==0)
    {};
    Serial.readBytes(Qu, 32);
    Serial.println("=> Input Random value ru <> Z*p: ");
    while(Serial.available()==0)
    {};
    Serial.readBytes(ru2, 32);
    //Output======
    Serial.println("Public key Qu: ");
    for(int i = 0; i <sizeof(Qu);++i)
    {
      Serial.printf("%02X", Qu[i]);
    };
    Serial.println();
    Serial.println("Random value ru <> Z*p: ");
    for(int i = 0; i <sizeof(ru2);++i)
    {
      Serial.printf("%02X", ru2[i]);
    };
    Serial.println();
    //=======
    Serial.print("Generating ... ");
    Serial.flush();
    start = micros();
    Curve25519::dh2(ru2, Qu);
    elapsed = micros() - start;
    Serial.print("elapsed ");
    Serial.print(elapsed);
    Serial.println(" us");
    Serial.println();
    //=======================SHARE SYMMETRIC KEY===========================
    Serial.println();
    Serial.println("RANDOM POINT Ru = ru*Qu = ");
    //Serial.println(sizeof(bob_pub));
    for(int i = 0; i < sizeof(ru2);++i)
    {
      Serial.printf("%02X", ru2[i]);
      Serial.print(" "); 
    };
    Serial.println(); 


       
  }else if(j == 2)
  { 
  //===============================STEP 5=====================================
  //Calculate SK = qu*ru*Rs
    //static byte SK[32]; // 
    static byte ru2[32];
    static byte qu[32];// 
    static byte Rs[32];
    Serial.println("=> Input User random value: ");
    while(Serial.available()==0)
    {};
    Serial.readBytes(ru2, 32);

    Serial.println("=> Input User Private key qu: ");
    while(Serial.available()==0)
    {};
    Serial.readBytes(qu, 32);

    Serial.println("=> Input Server random point value Rs: ");
    while(Serial.available()==0)
    {};
    Serial.readBytes(Rs, 32);

    Serial.println();
    Serial.print("Generate shared secret 2 ... ");
    Serial.flush();
    start = micros();
    Curve25519::dh2(ru2,qu);
    elapsed = micros() - start;
    Serial.println("SESION KEY SK lan 1 = qu*ru: ");
    for(int i = 0; i < sizeof(ru2);++i)
    {
      Serial.printf("%02X", ru2[i]);
      Serial.print(" "); 
    };
    Serial.flush();
    start = micros();
    Curve25519::dh2(Rs,ru2);
    elapsed = micros() - start;
    
    Serial.print("elapsed ");
    Serial.print(elapsed);
    Serial.println(" us");
    Serial.println();

    Serial.println();
    Serial.println("SESION KEY SK lan 2 = (qu*ru)*Rs: ");
    for(int i = 0; i < sizeof(Rs);++i)
    {
      Serial.printf("%02X", Rs[i]);
      Serial.print(" "); 
    };
    Serial.println();
  }
}

#endif 
