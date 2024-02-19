import time
import uuid
import http.client
import json
import hashlib
import base64
import hmac
import http
import secrets
import string
import pkce    # run command pip install pkce
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
# import jwt     # run command pip install pyjwt
from jose import jwt      # run command pip install python-jose
from jwcrypto import jwk, jwe    # run command pip install jwcrypto
from cryptography.x509 import load_pem_x509_certificate
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests   # run command pip install requests
from cryptography.hazmat.primitives import serialization
from integrationandOTVApp.models import CdVerifierAndNonce



def signin(request):
    return render(request, "signin.html")

token_request_uri = "https://epstg.meripehchaan.gov.in/openid/jwt/processJwtTokenRequest.do"
authGrantRequestUrl = "https://epstg.meripehchaan.gov.in/openid/jwt/processJwtAuthGrantRequest.do"
client_id = "10000XXXX"  # Your Service ID
aesKey = "813XXXX-XXXX-XXXX-XXXX-XXXXX68" # Your AES Key
certificate = "" # Your path to certficate

redirectionUri = "http://localhost:8000/views/processAuthCodeAndGetToken"
grant_type = "authorization_code"
scope = "openid"

# Method to craete AuthGrant request
def oidc_auth_code(request):
    state = ''.join(secrets.choice(string.ascii_uppercase + string.ascii_lowercase) for i in range(16))    # Must be unique and create new for each request
    nonce = uuid.uuid4().hex  # Create new randomly generated 32 characters string for every request
    code_verifier = pkce.generate_code_verifier(length=64)  # Create new randomly generated 64 characters string for every request
    cdVerifierAndNonce = CdVerifierAndNonce(code_verifier = code_verifier , nonce = nonce , stateId = state)  # Store the values in your DB
    cdVerifierAndNonce.save()
    code_challenge = pkce.get_code_challenge(code_verifier)
    response_type = "code"
    code_challenge_method = "S256"
    inputValue = ""+client_id+aesKey+state+nonce+redirectionUri+scope+code_challenge
    apiHmac = hashHMAChex(aesKey,inputValue)
    authRequestUrl = authGrantRequestUrl+"?scope="+scope+"&response_type="+response_type+"&redirect_uri="+redirectionUri+"&state="+state+"&code_challenge_method="+code_challenge_method+"&nonce="+nonce+"&client_id="+client_id+"&code_challenge="+code_challenge+"&request_uri="+authGrantRequestUrl+"&apiHmac="+apiHmac+""

    return redirect(authRequestUrl)


# Method to craete apiHmac
def hashHMAChex(key,value):

    message = bytes(value, 'utf-8')
    secret = bytes(key, 'utf-8')
    hash = hmac.new(secret, message, hashlib.sha256)
    var = base64.urlsafe_b64encode(hash.digest())
    apihmac = var.decode('utf-8')

    return apihmac



# Method to process authcode and create token Request
@csrf_exempt
def processAuthCodeAndGetToken(request):
    code = request.GET['code']
    state = request.GET['state']
    
    url = "epstg.meripehchaan.gov.in"
    
    code_verifier = ""
    nonce = ""
    
    try:
        cdVerifierAndNonce = CdVerifierAndNonce.objects.get(stateId = state)
        code_verifier = cdVerifierAndNonce.code_verifier
        nonce = cdVerifierAndNonce.nonce
       
    except CdVerifierAndNonce.DoesNotExist:
        print("CdVerifierAndNonce not found for the given state.")
    except CdVerifierAndNonce.MultipleObjectsReturned:
        print("Multiple CdVerifierAndNonce objects found for the given state. Handle this case as needed.")
        
    conn = http.client.HTTPSConnection(url)
    
    payload = json.dumps({
              "code": [
                        code
                      ],
              "grant_type": [
                       grant_type
                      ],
              "scope":[
                       scope
                      ],
              "redirect_uri": [
                       token_request_uri
                      ],
              "request_uri": [
                       redirectionUri
                      ],
              "code_verifier": [
                        code_verifier
                      ],
              "client_id": [
                        client_id
                      ]
})

    headers = {'Content-Type': 'application/json'}
    conn.request("POST", "/openid/jwt/processJwtTokenRequest.do", payload, headers)
    response = conn.getresponse()
    data = response.read()
    jweToken = data.decode('utf-8')
    base64urlencodedkey = base64.urlsafe_b64encode(hashlib.sha256(nonce.encode('utf-8')).digest()).decode()
    Startofkey='{"kty":"oct","k":"'
    endofkey='"}'
    jwkobjectkey="%s%s%s"%(Startofkey,base64urlencodedkey,endofkey)
    finalKey = jwk.JWK.from_json(jwkobjectkey)


    jwe_token = jwe.JWE()
    jwe_token.deserialize(jweToken)
    jwe_token.decrypt(finalKey)
    decrypted_payload = jwe_token.payload.decode()
    
    certificateData = open(certificate, "r").read().encode()
    cert = load_pem_x509_certificate(certificateData).public_key()
    key_str = cert.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

    jsonData = jwt.decode(decrypted_payload, key_str, algorithms=['RS256'], options={"verify_exp": True, "verify_aud": False})
    name = jsonData.get('name')
    username = jsonData.get('username')
    mobile_number = jsonData.get('mobile_number')
    email = jsonData.get('email')
    serviceUserId = jsonData.get('service_user_id')

    request.session['JWS'] = jsonData
    request.session.save()


    return render(request, "demo.html", {"fname":name,"username":username,"mobile_number":mobile_number,"email":email,"serviceUserId":serviceUserId})


salt = ""  # Declared gobally for One Time Verification
""" This Method required only when service chooses service_user_id Based Mapping(One Time Verification)
While service registration """
@csrf_exempt
def onetimeverificationforuser(request):

    sso_token = request.POST['ssoToken']
    print(sso_token)
    if sso_token is not None:
        seed = hashlib.sha256(aesKey.encode('utf-8')).digest()

        encryptedTextByte = base64.b64decode(sso_token)
        cipher = AES.new(seed, AES.MODE_ECB)
        decryptedText = cipher.decrypt(encryptedTextByte)

        decryptedText = decryptedText.decode('utf-8')
        decryptedText_data = decryptedText.rsplit('}', 1)[0]+'}'
        decryptedTextinjsonform = json.loads(decryptedText_data)
        print(decryptedTextinjsonform)

        global salt

        remainingString = decryptedText.rsplit('}', 1)[1]
        for i in remainingString:
            if i.isdigit() == True:
                salt = salt + i

        if 'sso_id' in decryptedTextinjsonform:
            sso_Id = decryptedTextinjsonform.get('sso_id')
        else:
            sso_Id = decryptedTextinjsonform.get('epramaanId')
        return render(request, "temp.html", {"Data":sso_Id})


# For One Time Verification
class EnrolSPServiceResponse:

    def __init__(self, responseTimestamp, serviceId, serviceUserId, transactionId, verified):
         self.responseTimestamp = responseTimestamp
         self.serviceId = serviceId
         self.serviceUserId = serviceUserId
         self.transactionId = transactionId
         self.verified = verified

    def __str__(self):
        return f"{self.responseTimestamp}{self.serviceId}{self.serviceUserId}{self.transactionId}{self.verified}"

    # getter method
    def getresponseTimestamp(self):
        return self.responseTimestamp

    # setter method
    def setresponseTimestamp(self, x):
        self.responseTimestamp = x

    # getter method
    def getserviceId(self):
        return self.serviceId

    # setter method
    def setserviceId(self, x):
        self.serviceId = x

    # getter method
    def getserviceUserId(self):
        return self.serviceUserId

    # setter method
    def setserviceUserId(self, x):
        self.serviceUserId = x

    # getter method
    def gettransactionId(self):
        return self.transactionId

    # setter method
    def settransactionId(self, x):
        self.transactionId = x

    # getter method
    def getverified(self):
        return self.verified

    # setter method
    def setverified(self, x):
        self.verified = x


# For One Time Verification
class EnrolSPServiceResponseWrapper:

    def __init__(self, encryptedEnrolSPServiceResponse, serviceId):
         self.encryptedEnrolSPServiceResponse = encryptedEnrolSPServiceResponse
         self.serviceId = serviceId
         #print(self.encryptedEnrolSPServiceResponse)

    def __str__(self):
        return f"{self.encryptedEnrolSPServiceResponse}{self.serviceId}"

    # getter method
    def getencryptedEnrolSPServiceResponse(self):
        return self.encryptedEnrolSPServiceResponse

    # setter method
    def setencryptedEnrolSPServiceResponse(self, x):
        self.encryptedEnrolSPServiceResponse = x

    # getter method
    def getserviceId(self):
        return self.serviceId

    # setter method
    def setserviceId(self, x):
        self.serviceId = x


""" This Method required only when service chooses service_user_id Based Mapping(One Time Verification)
While service registration """
@csrf_exempt
def onetimepushback(request):
    username = request.POST['username']
    sso_id = request.POST['sso_id']

    epramaanURL = "https://epstg.meripehchaan.gov.in/rest/epramaan/enrol/response"

    responseObject = EnrolSPServiceResponse(round(time.time()*1000), int(client_id), username, sso_id, True)
    responseJSON = str(json.dumps(responseObject.__dict__))+salt
    
    seed = hashlib.sha256(aesKey.encode('utf-8')).digest()
    cipher = AES.new(seed, AES.MODE_ECB)

    encryptedByte = cipher.encrypt(pad(responseJSON.encode('utf-8'), AES.block_size))
    encryptedtext = base64.b64encode(encryptedByte)
    encryptedEnrolSPServiceResponse = encryptedtext.decode("UTF-8")

    enrolSPServiceResponseWrapper = EnrolSPServiceResponseWrapper(encryptedEnrolSPServiceResponse, int(client_id))
    enrolSPServiceResponseWrapperinjsonform = json.dumps(enrolSPServiceResponseWrapper.__dict__)
    
    response = requests.post(epramaanURL, data=enrolSPServiceResponseWrapperinjsonform, headers={"Content-Type":"application/json"})

    if response.status_code == 200:
        return render(request, "success.html")
    else:
        return render(request, "error.html")


# Logout API for logging out user from ePramaan also
def logout( request):
    # (IMP)give url for logout while service registration
    logoutRequestId = uuid.uuid4(). hex
    session1 = request.session
    jsonString = session1.get('JWS')
    print( type( jsonString))
    print( "jsonString:", jsonString)

    sessionId = jsonString.get('session_id')

    iss = "ePramaan"
    sub = jsonString.get('sub')

    redirectUrl = "http://localhost:8000"

    inputValue = f"{ client_id }{ sessionId }{ iss }{ logoutRequestId }{ sub }{ redirectUrl }"

    hmac = hashHMAChex(logoutRequestId, inputValue)
    customParameter = ""

    url = "https://epstg.meripehchaan.gov.in/openid/jwt/processOIDCSLORequest.do"

    data = {
        "clientId": client_id,
        "sessionId": sessionId,
        "hmac": hmac,
        "iss": iss,
        "logoutRequestId": logoutRequestId,
        "sub": sub,
        "redirectUrl": redirectUrl,
        "customParameter": customParameter
    }

    print( type( data))

    print( "json string of data:", json.dumps( data))


    return render(request, "logout.html", {"redirectionURL": url, "data" : json.dumps( data)})