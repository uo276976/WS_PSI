#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "faster-csidh/csidh.h"

// Buffer sizes
#define PUBKEY_SIZE sizeof(public_key)
#define PRIVKEY_SIZE sizeof(private_key)
#define SHAREDKEY_SIZE sizeof(public_key)  // mismo tipo que pubkey

// Export a C-compatible function
void generate_key(uint8_t *pub_buf, uint8_t *priv_buf) {
    public_key pk;
    private_key sk = {0};
    csidh(&pk, &base, &sk);

    memcpy(pub_buf, &pk, PUBKEY_SIZE);
    memcpy(priv_buf, &sk, PRIVKEY_SIZE);
}

void derive_shared(uint8_t *shared_buf, uint8_t *peer_pub_buf, uint8_t *priv_buf) {
    public_key shared;
    public_key peer_pub;
    private_key priv;

    memcpy(&peer_pub, peer_pub_buf, PUBKEY_SIZE);
    memcpy(&priv, priv_buf, PRIVKEY_SIZE);

    csidh(&shared, &peer_pub, &priv);

    memcpy(shared_buf, &shared, SHAREDKEY_SIZE);
}
