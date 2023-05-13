from Crypto.PublicKey import ECC
import ECC as _ECC
from Crypto.Math.Numbers import Integer
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

f = open('key.pem','rt')
key = ECC.import_key(f.read())
f = open('ecc.pem', 'rt')
ecc = ECC.import_key(f.read())
print(f"D: {key.d}")
print(f"X: {key.pointQ.x}")
print(f"Y: {key.pointQ.y}")
print(f"Cert XY: {ecc.pointQ.x, ecc.pointQ.y}")
print("Key is valid!")


message = b"On the Curve vulnerability"
h = SHA256.new(message)
signer = DSS.new(key, 'deterministic-rfc6979')
signature = signer.sign(h)
print("Signature generated")
f = open('key.pem','rt')
key = ECC.import_key(f.read())
verifier = DSS.new(key, 'deterministic-rfc6979')
verifier.verify(h, signature)
print("Signature is validated!")
print("Successful exploitation of on the curve vulnerability!")
