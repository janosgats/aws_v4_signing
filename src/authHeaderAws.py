import sys, os, base64, datetime, hashlib, hmac, urllib
import requests # pip install requests
import appSecrets

object_key='untitled1'

method = 'GET'
service = 's3'
host = 'laboschqpa.s3.eu-central-1.amazonaws.com'
region = 'eu-central-1'
endpoint = 'https://laboschqpa.s3.eu-central-1.amazonaws.com/' + object_key
access_key = appSecrets.secretAccessKeys.get('aws').get('id')
secret_key = appSecrets.secretAccessKeys.get('aws').get('secret')
canonical_uri = '/' + object_key

# Key derivation functions. See:
# http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning

if access_key is None or secret_key is None:
    print('No access key is available.')
    sys.exit()

# Create a date for headers and the credential string
t = datetime.datetime.utcnow()
amz_date = t.strftime('%Y%m%dT%H%M%SZ') # Format date as YYYYMMDD'T'HHMMSS'Z'
datestamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope



algorithm = 'AWS4-HMAC-SHA256'
credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'

# Step 5: Create payload hash. For GET requests, the payload is an
# empty string ("").
payload_hash = hashlib.sha256(("").encode('utf-8')).hexdigest()

signed_headers = 'host;x-amz-content-sha256;x-amz-date'


canonical_headers = 'host:' + host + '\n'
canonical_headers += 'x-amz-content-sha256:' + payload_hash + '\n'
canonical_headers += 'x-amz-date:' + amz_date + '\n'

# Step 6: Combine elements to create canonical request
canonical_request = method + '\n' + canonical_uri + '\n' + '' + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash


print('------------------------------------------------------------')
print('canonical_request = ˇˇ ')
print(canonical_request)
print('------------------------------------------------------------')

# ************* TASK 2: CREATE THE STRING TO SIGN*************
string_to_sign = algorithm + '\n' +  amz_date + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
print('------------------------------------------------------------')
print('string_to_sign = ˇˇ ')
print(string_to_sign)
print('------------------------------------------------------------')


# ************* TASK 3: CALCULATE THE SIGNATURE *************
# Create the signing key
signing_key = getSignatureKey(secret_key, datestamp, region, service)

# Sign the string_to_sign using the signing_key
signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()


# ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************

authorization_header = 'AWS4-HMAC-SHA256 '
authorization_header += 'Credential=' + access_key + '/' + credential_scope + ','
authorization_header += 'SignedHeaders=' + signed_headers + ','
authorization_header += 'Signature=' + signature


# ************* SEND THE REQUEST *************
# The 'host' header is added automatically by the Python 'request' lib. But it
# must exist as a header in the request.
request_url = endpoint

print(authorization_header)

print('\nBEGIN REQUEST++++++++++++++++++++++++++++++++++++')
print('Request URL = ' + request_url)
s = requests.Session()
s.headers.update({'Authorization': authorization_header})
s.headers.update({'x-amz-content-sha256': payload_hash})
s.headers.update({'x-amz-date': amz_date})

r = s.get(request_url)

print('\nRESPONSE++++++++++++++++++++++++++++++++++++')
print('Response code: %d\n' % r.status_code)
print(r.text)
print('Response code: %d\n' % r.status_code)
print('Request URL = ' + request_url)