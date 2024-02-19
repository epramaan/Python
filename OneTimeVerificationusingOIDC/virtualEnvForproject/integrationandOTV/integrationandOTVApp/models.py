from django.db import models
# from django.utils import timezone

class CdVerifierAndNonce(models.Model) :
    code_verifier = models.CharField(max_length=255)
    nonce = models.CharField(max_length=255)
    stateId = models.CharField(max_length=255)
    
    
    
    
    
    
           