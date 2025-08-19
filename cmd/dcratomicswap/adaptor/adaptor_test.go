package adaptor

import (
	"math/rand"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
)

func TestAdaptorSignatureRandom(t *testing.T) {
	seed := time.Now().Unix()
	rng := rand.New(rand.NewSource(seed))
	defer func(t *testing.T, seed int64) {
		if t.Failed() {
			t.Logf("random seed: %d", seed)
		}
	}(t, seed)

	for i := 0; i < 100; i++ {
		// Generate two private keys
		var pkBuf1, pkBuf2 [32]byte
		if _, err := rng.Read(pkBuf1[:]); err != nil {
			t.Fatalf("failed to read random private key: %v", err)
		}
		if _, err := rng.Read(pkBuf2[:]); err != nil {
			t.Fatalf("failed to read random private key: %v", err)
		}
		var privKey1Scalar, privKey2Scalar secp256k1.ModNScalar
		privKey1Scalar.SetBytes(&pkBuf1)
		privKey2Scalar.SetBytes(&pkBuf2)
		privKey1 := secp256k1.NewPrivateKey(&privKey1Scalar)
		privKey2 := secp256k1.NewPrivateKey(&privKey2Scalar)

		// Generate random hashes to sign.
		var hash1, hash2 [32]byte
		if _, err := rng.Read(hash1[:]); err != nil {
			t.Fatalf("failed to read random hash: %v", err)
		}
		if _, err := rng.Read(hash2[:]); err != nil {
			t.Fatalf("failed to read random hash: %v", err)
		}

		// Generate random signature tweak
		var tBuf [32]byte
		if _, err := rng.Read(tBuf[:]); err != nil {
			t.Fatalf("failed to read random private key: %v", err)
		}
		var tweak secp256k1.ModNScalar
		tweak.SetBytes(&tBuf)

		// Sign hash1 with private key 1
		sig, err := schnorr.Sign(privKey1, hash1[:])
		if err != nil {
			t.Fatalf("Sign error: %v", err)
		}

		// The owner of priv key 1 knows the tweak. Sends a priv key tweaked adaptor sig
		// to the owner of priv key 2.
		adaptorSigPrivKeyTweak := PrivateKeyTweakedAdaptorSig(sig, privKey1.PubKey(), &tweak)
		err = adaptorSigPrivKeyTweak.Verify(hash1[:], privKey1.PubKey())
		if err != nil {
			t.Fatalf("verify error: %v", err)
		}

		// The owner of privKey2 creates a public key tweaked adaptor sig using
		// tweak * G, and sends it to the owner of privKey1.
		adaptorSigPubKeyTweak, err := PublicKeyTweakedAdaptorSig(privKey2, hash2[:], adaptorSigPrivKeyTweak.PublicTweak())
		if err != nil {
			t.Fatalf("PublicKeyTweakedAdaptorSig error: %v", err)
		}

		// The owner of privKey1 knows the tweak, so they can decrypt the
		// public key tweaked adaptor sig.
		decryptedSig, err := adaptorSigPubKeyTweak.Decrypt(&tweak, hash2[:])
		if err != nil {
			t.Fatal(err)
		}

		// Using the decrypted version of their sig, which has been made public,
		// the owner of privKey2 can recover the tweak.
		recoveredTweak, err := adaptorSigPubKeyTweak.RecoverTweak(decryptedSig)
		if err != nil {
			t.Fatal(err)
		}
		if !recoveredTweak.Equals(&tweak) {
			t.Fatalf("original tweak %v != recovered %v", tweak, recoveredTweak)
		}

		// Using the recovered tweak, the original priv key tweaked adaptor sig
		// can be decrypted.
		decryptedOriginalSig, err := adaptorSigPrivKeyTweak.Decrypt(&tweak, hash1[:])
		if err != nil {
			t.Fatal(err)
		}
		if valid := decryptedOriginalSig.Verify(hash1[:], privKey1.PubKey()); !valid {
			t.Fatal("decrypted original sig is invalid")
		}
	}
}

func RandomBytes(len int) []byte {
	bytes := make([]byte, len)
	_, err := rand.Read(bytes)
	if err != nil {
		panic("error reading random bytes: " + err.Error())
	}
	return bytes
}

func TestAdaptorSigParsing(t *testing.T) {
	adaptor := &AdaptorSignature{}
	adaptor.r.SetByteSlice(RandomBytes(32))
	adaptor.s.SetByteSlice(RandomBytes(32))
	adaptor.pubKeyTweak = true

	var tweak secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&adaptor.s, &tweak)

	serialized := adaptor.Serialize()

	adaptor2, err := ParseAdaptorSignature(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if !adaptor2.r.Equals(&adaptor.r) {
		t.Fatal("r mismatch")
	}
}
