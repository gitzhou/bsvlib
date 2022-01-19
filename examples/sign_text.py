from bsvlib import Key, verify_signed_text

private_key = Key('L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9')
text = 'hello world'

# sign arbitrary text with bitcoin private key
address, signature = private_key.sign_text(text)

# verify https://reinproject.org/bitcoin-signature-tool/
print(address, signature)

# verify
print(verify_signed_text(text, address, signature))
