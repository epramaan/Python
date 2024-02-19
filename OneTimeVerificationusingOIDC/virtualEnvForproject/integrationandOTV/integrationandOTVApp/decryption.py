#from jose import jwt
import hashlib
import base64
import jwt
from cryptography.hazmat.primitives import serialization
from jwcrypto import jwk, jwe
from cryptography.x509 import load_pem_x509_certificate

nonce = "Y29LekVQdldtTHZ1Zlc1cklMNnQyVUZ6RWNnMmZGZlQ=" 
certificate = "D:/python/ePramaan_IITP_PublicKey.crt"
jwetoken = "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiQTI1NktXIn0.MedEqtMDe5AfZwDf1VkbJdGiwFBsL0z42l4lkdlM4iDruKx2IPEJAw.WnVXv8Go4BWRjMxG.DycKIkt_Uk8Ac-7EAXTvqj2cr4tf-7FrnMxi3jDVTPEySrSpERYzYfXqLAhd0wQXSGVdx1lvBKEUFxKVheIUSENhX8xHMMEtbuHCyLqEkRqitpU4VKszxQPVB3RqfbolUGXcVP-RC5VJR6q2pyJtak6KTPzey-WdDD3eIcABF1GUmdYshk23ziZEbi0y9ZhW4OvBuD9PYM4xvnxdsaf_YcTr-Xqep6NdvlQIkJq8xPvUT8-yHwk6r9dkEiTtCMoBORgrj13nwsKqDjq_VCRjr_fJbH6OCRwZaUCNo7M5iXei7r3JaRpwQSQr0rv4OF9IZ7kIyM2boe8YsFS18avRwkgZM1NBCiASSzSmLo74v78UUNfZbtd0Jot98PMPlQva2e_qiGcExWoui3JjeI9MT0ypQFNDU-ChPzfzf5vN5YUzdV20FTkUx9XHDACANgqV8OlLOeSFLqaITASe1vT0YCVQS4l6yd6z4WtSzJZhNKfWnLpCFKVExW1QDI29--OWTQZfxXV0A8etomn5IAElXkoyMl9XdD_ri1m9XCcywem81SR7p1_g6U2xe2N_C5YF-ZOoHeotZckcLnvLLS7ItkmKTW6qw13lQRgn9VfWHHDRBgSh5c_n6caiqyv4Nlx9iJaU1c_niLV5uMtKzhMHt3bPM-R8ETa1-p4sxfg8Nz-ZgIwIa2w_MexdxkzFaZ7tvGbG1ZEGwcnhZPfrLds9FPw0f0LLTeuuifCoF7xtbTHwBTkaIZXb3x9EBO-NaQupm1hYk7QNs2YH-MEo_juSTly2NsOXTKbhs-rrN9lwUWA6ek_uWuEIBylqCelM4d1yjQhYakecobBklUZUpiw-7HS4za6OwWxxoNi7SxSnB_hnGxd8LqqAnSPsO5VYURku00QRn4I167IoN_oKyyWpxpzKSPhtQVjN_UJFrzyI_8OJkmmEy_0lit8xen_H2dhDiNdLerQP8yUMJBYjZBwRqEn8l6RYxjLaQVXZKy8xfFXMlXn1Hs-I954DSdKN9ybz3UW3ofbbJBf5FlBd5fR4t-TPE0MJrW5SYoqw7GHyAy4ru35UtRz6huyd9P11SHJ6n0wo20PGaQwRrDQ4y7bykjKn446FIDrJkBpdRZViQlEMZabXgsD0xRfB0gNbnaOgMh1eIgL7KsdhoSR9iSk.K-Xfeh35jRbr5ulG8MHNvQ"
# base64urlencodedkey = base64.urlsafe_b64encode(hashlib.sha256(nonce.encode('utf-8')).digest()).decode()
base64urlencodedkey = base64.b64encode(hashlib.sha256(nonce.encode('utf-8')).digest()).decode()
# finalbase64urlencodedkey = base64urlencodedkey.replace('+','-').replace('/','_').replace('=','')
Startofkey='{"kty":"oct","k":"'
endofkey='"}'
jwkobjectkey="%s%s%s"%(Startofkey,base64urlencodedkey,endofkey)
finalKey = jwk.JWK.from_json(jwkobjectkey)

jwe_token = jwe.JWE()
jwe_token.deserialize(jwetoken)
jwe_token.decrypt(finalKey)
decrypted_payload = jwe_token.payload.decode()
print("decrypted_payload ==",decrypted_payload)

certificateData = open(certificate, "r").read().encode()
cert = load_pem_x509_certificate(certificateData).public_key()

key_str = cert.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')


# dummy_key = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvB74sXYXmwKmkRK9s9kX\nMbn49c9aE8Kw1j6/5cTvBguR1ZmQ2UHmJFk8yANsRPOKX9kucmDclIU+P2HQlZyF\n71q2AhiaBXO0Jie2fbbk5EuR/Is0k0e0juXNRgx9sZvjsf/hZAhfOBIF1utZZlOo\n7GBYVeqZIrgY09R86p0rDpY9XK4J7oI91b9UClRf0Iz7NDWHm5AmT9/sPij0Wb5K\nY36eymjV6PqhjDyzazC//nO6FUM3A5DqNlmg8/QoHSZzAOk+gXExzl58TNY3o4pO\nGYuIab9BYmqyF10urx9VJkA4sG5r8vK80wOMLq6b8GGSuE/+mP8I1ocWK3CNM1DO\n1wIDAQAB\n-----END PUBLIC KEY-----'
decoded_token = None
try:
    decoded_token = jwt.decode(decrypted_payload, key_str, algorithms=['RS256'], options={"verify_exp": False, "verify_aud": False})
    # Token decoded successfully without signature verification

except Exception as e:
    # Handle other unexpected exceptions
    print(f"An error occurred during token decoding: {str(e)}")


print(decoded_token)