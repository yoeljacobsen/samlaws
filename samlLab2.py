#!/usr/bin/env python

import sys
#import boto.sts
import boto3
import boto3.s3
import requests
import getpass
import configparser
import base64
import logging
import xml.etree.ElementTree as ET
import re
import os
import sys
import getpass
from bs4 import BeautifulSoup
from os.path import expanduser
from urllib.parse import urlparse, urlunparse

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

##########################################################################
# Variables

# region: The default AWS region that this script will connect
# to for all API calls
region = 'ap-northeast-1'

# output format: The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = 'json'

# awscredfile: The file where this script will store the temp
# awsconffile: The file where this script will store the default config
# credentials under the saml profile
awscredfile = '/.aws/credentials'
awsconffile = '/.aws/config'

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should only be used for dev/test
sslverification = False

# idpentryurl: The initial url that starts the authentication process.
#idpentryurl = 'https://e-idp-auth-lab.weizmann.ac.il/nidp/saml2/idpsend?id=AWS'
#idpentryurl = 'https://e-idp-auth-lab.weizmann.ac.il/nidp/app/login?sid=0&sid=0'

# Uncomment to enable low level debugging
# logging.basicConfig(level=logging.DEBUG)

##########################################################################


# Initiate session handler
session = requests.Session()
print("Posting  Req")

# Am I running as part of a pam_exec process?
in_pam_exec = False

username = ''
password = ''

# Handle the pam_exec process. The username should be taken from the PAM_USER env variable
# and the password should be read from stdin
if 'PAM_USER' in os.environ.keys():
    username = os.environ['PAM_USER']
    if username != '':
        password = sys.stdin.read()
        if password != '':
            in_pam_exec = True
            #print("DEBUG: pam_exec style. User: {}, password: {}".format(username, password))
        else:
            print("DEBUG: pam_exec mode: Couldn't get any password from stdin")
            sys.exit(1)

# During normal execution, if the token is invalidated, this script must be call from any
# wrapper. In such case, the username is retrieved from the standard enniornment and the password
# is requested from the user
if not in_pam_exec:
	username = getpass.getuser()
	password = getpass.getpass('Your token has expired. Please retype your password: ')
	#print("DEBUG: NOT in pam_exec. User: {}, password: {}".format(username, password))

#payload = {
#    'option':'credential',
#    'Ecom_User_ID': 'aaext22',
#    'Ecom_Password': 'aaext22'
#}

payload = {
    'option':'credential',
    'Ecom_User_ID': username,
    'Ecom_Password': password
}

#print(payload)

idpauthformsubmiturl="https://e-idp-auth-lab.weizmann.ac.il/nidp/app/login?sid=0&sid=0"
#print(payload)
#response = session.post(
#    idpentryurl, data=payload, verify=sslverification)

# Performs the submission of the IdP login form with the above post data
headers = {'Content-type': 'application/x-www-form-urlencoded'}
response = session.post(
    idpauthformsubmiturl, data=payload, headers=headers, verify=sslverification)
#print("Response:")
#print(response.text.decode('utf8'))

#idpauthformsubmiturl='https://e-idp-auth-lab.weizmann.ac.il/nidp/app?sid=0'
idpentryurl = 'https://e-idp-auth-lab.weizmann.ac.il/nidp/saml2/idpsend?id=AWS'
response = session.get(
    idpentryurl, headers=headers, verify=sslverification)

#print("Response:")
#print(response.text.decode('utf8'))

# Decode the response and extract the SAML assertion
#soup = BeautifulSoup(response.text.decode('utf8'),'html.parser')
soup = BeautifulSoup(response.text,'html.parser')
assertion = ''

# Look for the SAMLResponse attribute of the input tag (determined by
# analyzing the debug print lines above)
for inputtag in soup.find_all('input'):
    if(inputtag.get('name') == 'SAMLResponse'):
        #print(inputtag.get('value'))
        assertion = inputtag.get('value')

# Better error handling is required for production use.
if (assertion == ''):
    #TODO: Insert valid error checking/handling
    print('Response did not contain a valid SAML assertion')
    sys.exit(0)

#print(assertion)
# Parse the returned assertion and extract the authorized roles
awsroles = []
root = ET.fromstring(base64.b64decode(assertion))
for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            awsroles.append(saml2attributevalue.text)

# Note the format of the attribute value should be role_arn,principal_arn
# but lots of blogs list it as principal_arn,role_arn so let's reverse
# them if needed
for awsrole in awsroles:
    chunks = awsrole.split(',')
    if'saml-provider' in chunks[0]:
        newawsrole = chunks[1] + ',' + chunks[0]
        index = awsroles.index(awsrole)
        awsroles.insert(index, newawsrole)
        awsroles.remove(awsrole)

# If I have more than one role, ask the user which one they want,
# otherwise just proceed
print()
if len(awsroles) > 1:
    i = 0
    print("Please choose the role you would like to assume:")
    for awsrole in awsroles:
        print('[', i, ']: ', awsrole.split(',')[0])
        i += 1
    print("Selection: ",)
    selectedroleindex = raw_input()

    # Basic sanity check of input
    if int(selectedroleindex) > (len(awsroles) - 1):
        print('You selected an invalid role index, please try again')
        sys.exit(0)

    role_arn = awsroles[int(selectedroleindex)].split(',')[0]
    principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
else:
    role_arn = awsroles[0].split(',')[0]
    principal_arn = awsroles[0].split(',')[1]

print(role_arn)
print(principal_arn)


stsclient = boto3.client('sts')
token  = stsclient.assume_role_with_saml(RoleArn=role_arn, PrincipalArn=principal_arn, SAMLAssertion=assertion)
print(token['Credentials']['SecretAccessKey'])

# Write the AWS STS token into the AWS credential file
home = expanduser("~" + username)
credfilename = home + awscredfile
conffilename = home + awsconffile

# Make sure the directory exists
hn, tn = os.path.split(credfilename)
os.makedirs(hn, exist_ok=True)

# Read in the existing config file
cred = configparser.RawConfigParser()
cred.read(credfilename)
conf = configparser.RawConfigParser()
conf.read(conffilename)

# Put the credentials into a saml specific section instead of clobbering
# the default credentials
if not cred.has_section('saml'):
    cred.add_section('saml')
if not conf.has_section('saml'):
    conf.add_section('saml')

# Config file
conf.set('saml', 'output', outputformat)
conf.set('saml', 'region', region)

# Credentials
cred.set('saml', 'aws_access_key_id', token['Credentials']['AccessKeyId'])
cred.set('saml', 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
cred.set('saml', 'aws_session_token', token['Credentials']['SessionToken'])

# Write the updated config and credentials file
with open(credfilename, 'w+') as credfile:
    cred.write(credfile)
with open(conffilename, 'w+') as conffile:
    conf.write(conffile)

# Give the user some basic info as to what has just happened
print('\n\n----------------------------------------------------------------')
print('Your new access key pair has been stored in the AWS configuration file {0} under the saml profile.'.format(credfilename))
print('Note that it will expire at {0}.'.format(token['Credentials']['Expiration']))
print('After this time, you may safely rerun this script to refresh your access key pair.')
print('To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile saml ec2 describe-instances).')
print('----------------------------------------------------------------\n\n')

#session = boto3.Session(profile_name='saml')
# Any clients created from this session will use credentials
# from the [dev] section of ~/.aws/credentials.
#s3_client = session.client('s3')

#response = s3_client.list_buckets()
#buckets = [bucket['Name'] for bucket in response['Buckets']]
#
#print('Simple API example listing all S3 buckets:')
#print("\n".join(buckets))

