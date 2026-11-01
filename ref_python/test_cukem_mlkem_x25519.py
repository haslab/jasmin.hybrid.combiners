from cukem_mlkem_x25519 import KeyGen, Encaps, Decaps


for _ in range(100):
    sk, pk = KeyGen()

    ss, c = Encaps(pk)

    assert Decaps(sk, c) == ss
