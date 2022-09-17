- 👋 Hi, I’m @187sec
- 👀 I’m interested in ...
- 🌱 I’m currently learning ...
- 💞️ I’m looking to collaborate on ...
- 📫 How to reach me ...

<!---
187sec/187sec is a ✨ special ✨ repository because its `README.md` (this file) appears on your GitHub profile.
You can click the Preview link to take a look at your changes.
--->
END-OF-HEADER -----------------------------

File        : MAIN_SERVER.c
Purpose     : Demonstrate how to setup a server/ client with E2EE using emCrypt.
*/

/*********************************************************************
*
*       #include section
*
**********************************************************************
*/

#include "CRYPTO.h"
#include "SYS.h"
#include <stdio.h>
#include <stdlib.h>

/*********************************************************************
*
*       Defines, fixed
*
**********************************************************************
*/
#define MODE_NONE 0
#define MODE_OFB  1
#define MODE_CCM  2

/*********************************************************************
*
*       Defines, configurable
*
**********************************************************************
*/
#define AES_MODE  MODE_OFB


#define COPYRIGHT_STRING      "emCrypt Communication Sample, (c) 2019 SEGGER Microcontroller GmbH."
#define DEFAULT_PASSWORD      "Secret"    // Default password
#define SERVER_LISTENER_PORT  (19099)     // TCP/IP port that server listens to
#define MAX_MSG_LEN           (2048)      // Maximum size (bytes) for a message. This includes a terminating \0.
#define MAX_MSG_OVERHEAD      (128)       // Maximum overhead from the encryption algorithm which is sent in addition th the message.
#define SERVER_CONN_ACCEPT    (0x00)      // Value sent by server on success
#define SERVER_CONN_DENY      (0xFF)      // Value sent by server on fail
#define TAG_LEN               16          // TagLen must be 4, 6, 8, 10, 12, 14, or 16.
#define IV_LEN                8           // Length of IV for CCM Mode. Must be between 7 and 13

/*********************************************************************
*
*       Local types
*
**********************************************************************
*/
typedef struct {
  CRYPTO_AES_CONTEXT CipherContext;
#if AES_MODE == MODE_OFB
  U8 aBlock[CRYPTO_AES_BLOCK_SIZE];
  unsigned Index;
#elif AES_MODE == MODE_CCM
  U8* pIV;
#endif
} KEYSTREAM;

typedef struct {
  U8  abPassword[32];
  U32 PasswordLen;
  U8  abSalt[16];
  U32 SaltLen;
  struct {
    U8 aToClientKey[CRYPTO_AES256_KEY_SIZE];
    U8 aToClientIV[CRYPTO_AES_BLOCK_SIZE];
    U8 aToServerKey[CRYPTO_AES256_KEY_SIZE];
    U8 aToServerIV[CRYPTO_AES_BLOCK_SIZE];
  } Session;
  // 
  KEYSTREAM ToClientKeystream;
  KEYSTREAM ToServerKeystream;
} CONNECTION_STATE;

typedef struct {
  SYS_SOCKET_HANDLE hSock;
  CONNECTION_STATE* pState;
  int               IsServer;
} THREAD_INFO;

/*********************************************************************
*
*       Static data
*
**********************************************************************
*/

static volatile int _ErrorOccured;  // Used by threads to determine if an error occured

/*********************************************************************
*
*       Static code
*
**********************************************************************
*/

/*********************************************************************
*
*       _DeriveKey()
*
*  Function description
*    Derive session keys.
*
*  Parameters
*    pState - Pointer to connection state.
*/
static void _DeriveKey(CONNECTION_STATE *pState) {
  //
  // Derive session data from "shared secret"
  //
  CRYPTO_PBKDF2_HMAC_SHA256_Calc(pState->abSalt, pState->SaltLen,
                                 pState->abPassword, pState->PasswordLen,
                                 10000,
                                 (U8 *)&pState->Session, sizeof(pState->Session));
  
  CRYPTO_AES_InitEncrypt(&pState->ToClientKeystream.CipherContext, pState->Session.aToClientKey, sizeof(pState->Session.aToClientKey));
  CRYPTO_AES_InitEncrypt(&pState->ToServerKeystream.CipherContext, pState->Session.aToServerKey, sizeof(pState->Session.aToServerKey));
#if AES_MODE == MODE_OFB
  CRYPTO_AES_Encrypt(&pState->ToClientKeystream.CipherContext, pState->ToClientKeystream.aBlock, pState->Session.aToClientIV);
  CRYPTO_AES_Encrypt(&pState->ToServerKeystream.CipherContext, pState->ToServerKeystream.aBlock, pState->Session.aToServerIV);
  pState->ToClientKeystream.Index = 0;
  pState->ToServerKeystream.Index = 0;
#elif AES_MODE == MODE_CCM
  pState->ToClientKeystream.pIV = pState->Session.aToClientIV;
  pState->ToServerKeystream.pIV = pState->Session.aToServerIV;
#endif

}

/*********************************************************************
*
*       _Encrypt()
*
*  Function description
*    Encrypt plain data.
*
*  Parameters
*    pState   - Pointer to connection state.
*    pSrc     - Source buffer.
*    pDest    - Destination buffer.
*    NumBytes - Length of buffers in bytes.
* 
*  Return Value
*    >= 0: Number of bytes to be sent.
*/
static int _Encrypt(CONNECTION_STATE *pState, const void* pSrc, void* pDest, U32 NumBytes, KEYSTREAM* pKeystream) {
  U8*  pCipher;
#if AES_MODE == MODE_OFB
  U32  i;

  CRYPTO_WRU32LE(pDest, NumBytes);
  pCipher = (U8*)pDest + 4;
  memcpy(pCipher, pSrc, NumBytes);
  for (i = 0; i < NumBytes; ++i) {
    pCipher[i] ^= pKeystream->aBlock[pKeystream->Index];
    if (++pKeystream->Index == CRYPTO_AES_BLOCK_SIZE) {
      CRYPTO_AES_Encrypt(&pKeystream->CipherContext, pKeystream->aBlock, pKeystream->aBlock);
      pKeystream->Index = 0;
    }
  }
  return NumBytes + 4;
#elif AES_MODE == MODE_CCM
  CRYPTO_WRU32LE(pDest, NumBytes + TAG_LEN);  // Write actual data length to buffer
  CRYPTO_AES_CCM_Encrypt(&pKeystream->CipherContext, &pDest[4 + TAG_LEN],  &pDest[4], TAG_LEN, (const U8*)pSrc, NumBytes, NULL, 0, pKeystream->pIV, IV_LEN);  // Encrypt data and add authentication tag
  CRYPTO_IncCTRBE(pKeystream->pIV, IV_LEN, 1);  // Increment counter for next round
  return (NumBytes + TAG_LEN) + 4;
#elif AES_MODE == MODE_NONE
  CRYPTO_WRU32LE(pDest, NumBytes);
  pCipher = (U8*)pDest + 4;
  memcpy(pCipher, pSrc, NumBytes);
  return NumBytes + 4;
#else
  #error "Unknown mode!"
#endif
}


/*********************************************************************
*
*       _Decrypt()
*
*  Function description
*    Decrypt encrypted data.
*
*  Parameters
*    pState   - Pointer to connection state.
*    pSrc     - Source buffer.
*    pDest    - Destination buffer.
*    NumBytes - Length of buffers in bytes.
*
*  Return Value
*   == 0: OK. (in CCM Mode: Calculated tag and given tag are identical).
*   != 0: Error (in CCM Mode: Calculated tag and given tag are not identical).
*/
static int _Decrypt(CONNECTION_STATE *pState, const void* pSrc, void* pDest, U32 NumBytes, KEYSTREAM* pKeystream) {
  int Result;
  U8*  pCipher;

#if AES_MODE == MODE_OFB
  U32  i;

  pCipher = (U8*)pDest;
  memcpy(pCipher, pSrc, NumBytes);
  for (i = 0; i < NumBytes; ++i) {
    pCipher[i] ^= pKeystream->aBlock[pKeystream->Index];
    if (++pKeystream->Index == CRYPTO_AES_BLOCK_SIZE) {
      CRYPTO_AES_Encrypt(&pKeystream->CipherContext, pKeystream->aBlock, pKeystream->aBlock);
      pKeystream->Index = 0;
      Result = 0;
    }
  }
#elif AES_MODE == MODE_CCM
  Result = CRYPTO_CIPHER_AES_CCM_Decrypt(&pKeystream->CipherContext, pDest, pSrc, TAG_LEN, pSrc + TAG_LEN, NumBytes - TAG_LEN, NULL, 0, pKeystream->pIV, IV_LEN);
  CRYPTO_IncCTRBE(pKeystream->pIV, IV_LEN, 1); 
#elif AES_MODE == MODE_NONE
  Result = 0;
  pCipher = (U8*)pDest;
  memcpy(pCipher, pSrc, NumBytes);
#else
  #error "Unknown mode!"
#endif

return Result;
}
