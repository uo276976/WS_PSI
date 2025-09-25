#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "faster-csidh/csidh.h"

// Buffer sizes
#define PUBKEY_SIZE sizeof(public_key)
#define PRIVKEY_SIZE sizeof(private_key)
#define SHAREDKEY_SIZE sizeof(public_key)

extern const public_key base;

static inline int8_t rand_small()
{
    return (rand() % 11) - 5;
}

void generate_key(uint8_t *pub_buf, uint8_t *priv_buf)
{
    public_key pk;
    private_key sk;

    srand((unsigned int) time(NULL));

    for (size_t i = 0; i < sizeof(sk.e)/sizeof(sk.e[0]); ++i)
    {
        sk.e[i] = rand_small();
    }

    csidh(&pk, &base, &sk);

    memcpy(pub_buf, &pk, PUBKEY_SIZE);
    memcpy(priv_buf, &sk, PRIVKEY_SIZE);
}

void derive_shared(uint8_t *shared_buf, uint8_t *peer_pub_buf, uint8_t *priv_buf)
{
    public_key shared;
    public_key peer_pub;
    private_key priv;

    memcpy(&peer_pub, peer_pub_buf, PUBKEY_SIZE);
    memcpy(&priv, priv_buf, PRIVKEY_SIZE);

    csidh(&shared, &peer_pub, &priv);

    memcpy(shared_buf, &shared, SHAREDKEY_SIZE);
}

size_t csidh_pubkey_size(void)  { return sizeof(public_key);  }
size_t csidh_privkey_size(void) { return sizeof(private_key); }
size_t csidh_shared_size(void)  { return sizeof(public_key);  }
