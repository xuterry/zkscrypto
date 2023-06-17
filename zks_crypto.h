#define FFI_LIB "zks_crypto.so"
#define FFI_SCOPE "Zkscrypto"
typedef enum MUSIG_SIGN_RES {
  MUSIG_SIGN_OK = 0,
  MUSIG_SIGN_MSG_TOO_LONG,
} MUSIG_SIGN_RES;
typedef enum MUSIG_VERIFY_RES {
  MUSIG_VERIFY_OK = 0,
  MUSIG_VERIFY_FAILED,
} MUSIG_VERIFY_RES;
typedef enum PRIVATE_KEY_FROM_SEED_RES {
  PRIVATE_KEY_FROM_SEED_OK = 0,
  PRIVATE_KEY_FROM_SEED_SEED_TOO_SHORT,
} PRIVATE_KEY_FROM_SEED_RES;
typedef enum PUBKEY_HASH_FROM_PUBKEY_RES {
  PUBKEY_HASH_FROM_PUBKEY_OK = 0,
} PUBKEY_HASH_FROM_PUBKEY_RES;
typedef enum PUBLIC_KEY_FROM_PRIVATE_RES {
  PUBLIC_KEY_FROM_PRIVATE_OK = 0,
} PUBLIC_KEY_FROM_PRIVATE_RES;
typedef struct ZksResqueHash {
  uint8_t data[31];
} ZksResqueHash;
typedef struct ZksPrivateKey {
  uint8_t data[32];
} ZksPrivateKey;
typedef struct ZksPackedPublicKey {
  uint8_t data[32];
} ZksPackedPublicKey;
typedef struct ZksPubkeyHash {
  uint8_t data[20];
} ZksPubkeyHash;
typedef struct ZksSignature {
  uint8_t data[64];
} ZksSignature;
void rescue_hash_orders(const uint8_t *msg, size_t msg_len, ZksResqueHash *hash);
void zks_crypto_init(void);
PRIVATE_KEY_FROM_SEED_RES zks_crypto_private_key_from_seed(const uint8_t *seed,
                                                           size_t seed_len,
                                                           ZksPrivateKey *private_key);
PUBLIC_KEY_FROM_PRIVATE_RES zks_crypto_private_key_to_public_key(const ZksPrivateKey *private_key,
                                                                 ZksPackedPublicKey *public_key);
PUBKEY_HASH_FROM_PUBKEY_RES zks_crypto_public_key_to_pubkey_hash(const ZksPackedPublicKey *public_key,
                                                                 ZksPubkeyHash *pubkey_hash);
MUSIG_SIGN_RES zks_crypto_sign_musig(const ZksPrivateKey *private_key,
                                     const uint8_t *msg,
                                     size_t msg_len,
                                     ZksSignature *signature_output);
MUSIG_VERIFY_RES zks_crypto_verify_musig(const uint8_t *msg,
                                         size_t msg_len,
                                         const ZksPackedPublicKey *public_key,
                                         const ZksSignature *signature);