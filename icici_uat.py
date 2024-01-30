# CIB registration >> Payment initiation >> Status check
from curses.ascii import RS
from email import message
from unittest.mock import sentinel
from cryptography.hazmat.backends import default_backend
import requests
import json
import rsa
import random
from base64 import b64encode
from base64 import b64decode
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import PKCS1_v1_5
# from cryptography.hazmat.primitives.asymmetric import rsa, padding


def cib_registration():
	API_KEY = "UdaTGSybywWQn346U2yBt6xqukbwRjOg"
	url = "https://apibankingonesandbox.icicibank.com/api/Corporate/CIB/v1/Registration"

	headers = {
			"apikey":API_KEY
	}

	payload = {
			"CORPID": "PRACHICIB1",
			"USERID": "USER3",
			"AGGRNAME": "GOLDPRIVATE",
			"AGGRID": "TXBCOMP0130",
			"URN": "SR238737998"
	}

	#final integration part: ENCRYPTION PROCESS
	session_key = str(random.randrange(100000000000000,200000000000000))

	#generate encryption key
	encrypted_key = rsa_encrypt(session_key)

	response =  requests.post(url=url, headers=headers, data=payload).json()

	if response.ok:
		print(f"User has been registered successfully {response.message}")
		return response

def initiate_payment(paymentService):
		API_KEY = "Mn8p9oyLAjCc9Xsuq7ksXpmoZA9kQx5L"
		priority_value = ""
		if paymentService == "NEFT":
				priority_value = "0010"
		if paymentService == "RTGS":
				priority_value = "0001"

		url = " https://apibankingonesandbox.icicibank.com/api/v1/composite-payment/"

		headers = {
				"apikey":API_KEY,
				"x-priority":priority_value
				}

		#generating random dummy values
		tran_ref_no = random.randrange(100000000000000,200000000000000)


		payload = {
				"tranRefNo": str(tran_ref_no),
				"amount": "1.00",
				"senderAcctNo": "000451000301",
				"beneAccNo": "000405002777",
				"beneName": "PratikMundhe",
				"beneIFSC": "ICIC0000011",
				"narration1": "NEFT UAT transaction",
				"narration2": "PritamG",
				"crpId": "PRACHICIB1",
				"crpUsr": "389018",
				"aggrId": "TXBCOMP0130",
				"aggrName": "GOLDPRIVATE",
				"urn": "SR238737998",
				"txnType": "RGS",
				"WORKFLOW_REQD": "N"
				}

		response = requests.post(url=url, headers=headers, data=payload)

		if response.ok:
				print(f"Payment has been initiated successfully {response.message}")
				return response


def rsa_encrypt(sessionKey):
	print("Session Key : ", sessionKey)
	with open('.ssh/pub.txt', 'rb') as f:
		data = f.read()
		public_key =  rsa.PublicKey.load_pkcs1(data)
		encrypted_key = rsa.encrypt(sessionKey.encode('utf-8'), public_key)
		key = RSA.importKey(data)
		cipher = PKCS1_v1_5.new(key)
		ciphertext = cipher.encrypt(bytes(sessionKey, 'utf-8'))
		return ciphertext

def rsa_decrypt(encryptedKey):
	with open('.ssh/id_rsa','rb') as f:
		key = f.read()
		private_key = RSA.importKey(key)
		cipher = PKCS1_v1_5.new(private_key)
		
		sentinel = get_random_bytes(16)
		message = cipher.decrypt(encryptedKey, sentinel)
		print("Decrypted Key : ", str(message, 'utf-8'))
		return message

if __name__ == '__main__':
	#generating a random number with range of 16
	session_key = str(random.randrange(100000000000000,200000000000000))

	#encrypting the session key using rsa public key
	encrypted_key = rsa_encrypt(session_key)

	#decrypting the encrypted key using private key
	rsa_decrypt(encryptedKey=encrypted_key)