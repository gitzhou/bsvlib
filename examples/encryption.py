from bsvlib import Key

private_key = Key('L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9')
public_key = private_key.public_key()

plain = 'hello world'

# use public key to encrypt
encrypted = public_key.encrypt_text(plain)
print(encrypted)

# decrypt with the corresponding private key
print(private_key.decrypt_text(encrypted))
