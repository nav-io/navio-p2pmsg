# BIP324 test vectors

Copied verbatim from the BIP repository
(<https://github.com/bitcoin/bips/tree/master/bip-0324>) so the tests are
hermetic and do not reach the network.

| file | what it pins |
|---|---|
| `ellswift_decode_test_vectors.csv` | `xswiftec`: 64-byte ElligatorSwift input → X coordinate, including every degenerate branch (u or t ≡ 0, u³+t²+7 ≡ 0, non-canonical inputs above p) |
| `xswiftec_inv_test_vectors.csv` | the inverse map, per `case` 0..7, including the cases that must fail |
| `packet_encoding_test_vectors.csv` | the whole v2 transport: ECDH, HKDF-derived keys, garbage terminators, session id, and packet ciphertext after N packets of rekeying |

These are the only reason to trust the implementation. An ElligatorSwift map
that is subtly wrong still produces plausible-looking 64-byte blobs, and an
off-by-one in the rekey schedule only shows up after 224 packets.
