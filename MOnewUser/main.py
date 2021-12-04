#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Nov 28 20:37:51 2021

@author: juliocesar
"""

####################################
##### Smart Contract functions #####
####################################

# url for connection with blockchain
url = 'HTTP://127.0.0.1:7545'
url = 'https://ropsten.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161'

# Smart contract address and ABI
smartContractAddr = "0x054e26bF9654Aef2c84457Da6F7fa29205B1ec68"


from web3 import Web3

def connectToBlockchain(url, contract_addr, contract_abi):
    w3 = Web3(Web3.HTTPProvider(url))
    counter = w3.eth.contract(address=contract_addr,abi=contract_abi)
    return counter, w3

def resetAddr(MOId, newAddr, priv_key, pub_key, contract, w3):
    address = Web3.toChecksumAddress(pub_key)
    nonce = w3.eth.getTransactionCount(address)
    transaction = contract.functions.resetAddr(MOId,newAddr).buildTransaction({
        'gas': 70000,
        'gasPrice': w3.toWei('2.5', 'gwei'),
        'from': pub_key,
        'nonce': nonce
        })
    signed_txn = w3.eth.account.signTransaction(transaction, private_key=priv_key)
    tx_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
    return tx_hash

def resetEmail(MOId, newEmail, priv_key, pub_key, contract, w3):
    address = Web3.toChecksumAddress(pub_key)
    nonce = w3.eth.getTransactionCount(address)
    transaction = contract.functions.resetEmail(MOId,newEmail).buildTransaction({
        'gas': 70000,
        'gasPrice': w3.toWei('2.5', 'gwei'),
        'from': pub_key,
        'nonce': nonce
        })
    signed_txn = w3.eth.account.signTransaction(transaction, private_key=priv_key)
    tx_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
    return tx_hash

def resetPublicKey(MOId, newPublicKey, priv_key, pub_key, contract, w3):
    address = Web3.toChecksumAddress(pub_key)
    nonce = w3.eth.getTransactionCount(address)
    transaction = contract.functions.resetPublicKey(MOId,newPublicKey).buildTransaction({
        'gas': 700000,
        'gasPrice': w3.toWei('2.5', 'gwei'),
        'from': pub_key,
        'nonce': nonce
        })
    signed_txn = w3.eth.account.signTransaction(transaction, private_key=priv_key)
    tx_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
    return tx_hash

def getMilitaryOrganization(MOId, contract):
    return contract.functions.getMilitaryOrganization(MOId).call()

def getWallet(walletPath = "./Wallet/"):
    a_file = open(walletPath + "priv_wallet.txt")
    priv_wallet = a_file.read()
    b_file = open(walletPath + "pub_wallet.txt")
    pub_wallet = b_file.read()
    return priv_wallet, pub_wallet

priv_wallet, pub_wallet = getWallet()

#public_key = f'''-----BEGIN PUBLIC KEY-----
#MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtHGMN5Cvs1Cldz+VWaO9
#S80nk5MRyxebQoCKaSN1GJjkMlqA46bRqnQkbCEeV4vuIwrFpOutUhul5vORZT2R
#hwc2GwFaNmS6qoxoBtN60Iy0HrnJGK2GeLvNTOpuQduHA3ciddIQqyYszNB7uavD
#NI5wuClIEM8DUIqNDdwuP6Id7Lyq5XyuGdI5yX+0e3PX46jxrPV+cErpzZDp4EjR
#V5jCu8fZNZByKvW6aMm7d7uiTKJ/ohHdeNskvdaYvIhTUMcfLKOOhtg32r+ztpFm
#v24RVu+DJukMtoKsaDhHgGIDSC4StYTvjqVdVNXFQKio6SvRrfDZLKmNK3m/Udus
#AwIDAQAB
#-----END PUBLIC KEY-----'''

#public_keyString = str(public_key)

# url for connection with blockchain
#url = 'HTTP://127.0.0.1:7545'

# Smart contract address and ABI
#smartContractAddr = "0xde7C6a0dCDC8b033d045B73d7c0a134cDFa476C5"
smartContractABI = [
	{
		"constant": True,
		"inputs": [],
		"name": "PKtechnicalUsersCount",
		"outputs": [
			{
				"name": "",
				"type": "uint256"
			}
		],
		"payable": False,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": True,
		"inputs": [
			{
				"name": "",
				"type": "uint256"
			}
		],
		"name": "MilitaryOrganizationRegistered",
		"outputs": [
			{
				"name": "",
				"type": "bool"
			}
		],
		"payable": False,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": True,
		"inputs": [],
		"name": "MilitaryOrganizationRegisteredCount",
		"outputs": [
			{
				"name": "",
				"type": "uint256"
			}
		],
		"payable": False,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": False,
		"inputs": [
			{
				"name": "_id",
				"type": "uint256"
			},
			{
				"name": "_publicKey",
				"type": "string"
			}
		],
		"name": "resetPublicKey",
		"outputs": [],
		"payable": False,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": False,
		"inputs": [
			{
				"name": "_id",
				"type": "uint256"
			},
			{
				"name": "_addr",
				"type": "address"
			}
		],
		"name": "resetAddr",
		"outputs": [],
		"payable": False,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": False,
		"inputs": [
			{
				"name": "_id",
				"type": "uint256"
			},
			{
				"name": "_email",
				"type": "string"
			}
		],
		"name": "resetEmail",
		"outputs": [],
		"payable": False,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": True,
		"inputs": [
			{
				"name": "_id",
				"type": "uint256"
			}
		],
		"name": "getMilitaryOrganization",
		"outputs": [
			{
				"name": "",
				"type": "uint256"
			},
			{
				"name": "",
				"type": "string"
			},
			{
				"name": "",
				"type": "address"
			},
			{
				"name": "",
				"type": "string"
			},
			{
				"name": "",
				"type": "string"
			}
		],
		"payable": False,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": False,
		"inputs": [
			{
				"name": "_id",
				"type": "uint256"
			},
			{
				"name": "_name",
				"type": "string"
			},
			{
				"name": "_addr",
				"type": "address"
			},
			{
				"name": "_email",
				"type": "string"
			},
			{
				"name": "_pubkey",
				"type": "string"
			}
		],
		"name": "createMilitaryOrganization",
		"outputs": [],
		"payable": False,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": True,
		"inputs": [
			{
				"name": "",
				"type": "uint256"
			}
		],
		"name": "MilitaryOrganizations",
		"outputs": [
			{
				"name": "id",
				"type": "uint256"
			},
			{
				"name": "name",
				"type": "string"
			},
			{
				"name": "addr",
				"type": "address"
			},
			{
				"name": "email",
				"type": "string"
			},
			{
				"name": "publicKey",
				"type": "string"
			}
		],
		"payable": False,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": True,
		"inputs": [
			{
				"name": "",
				"type": "address"
			}
		],
		"name": "PKtechnicalUsers",
		"outputs": [
			{
				"name": "",
				"type": "bool"
			}
		],
		"payable": False,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"payable": False,
		"stateMutability": "nonpayable",
		"type": "constructor"
	}
]

#MOId = 11031


# Start connection to a smart contract
contract, w3 = connectToBlockchain(url, smartContractAddr, smartContractABI)

# Use contract functions
#tx_hash = resetEmail(11031, "teste_email", priv_key, pub_addr, contract, w3)
#resetPublicKey(11031, public_keyString, priv_key, pub_addr, contract, w3)
#resetAddr(11031, '0xa636B909f8Dc044c7281aad6A87A6C8AfE9B2ba3', priv_key, pub_addr, contract, w3)

#print(getMilitaryOrganization(11031, contract))





#a_wallet_priv = 'fcba43107d89934ccf9db525e60cb8a0b204df4cd25a4882392c3e5647dcf6ba'
#a_wallet_addr = '0xa636B909f8Dc044c7281aad6A87A6C8AfE9B2ba3'

'''
WalletPubFile = open('./Wallet/pub_wallet.txt', "rb")
WalletPubContent = WalletPubFile.read().decode("utf-8")
print(WalletPubContent)

WalletPrivFile = open('./Wallet/priv_wallet.txt', "rb")
WalletPrivContent = WalletPrivFile.read().decode("utf-8")
print(WalletPrivContent)

PGPpublicKeyFile = open('./PGP/publickey.pem', "rb")
PGPpublicKeyContent = PGPpublicKeyFile.read().decode("utf-8")
print(PGPpublicKeyContent)

resetPublicKey(11032, PGPpublicKeyContent, WalletPrivContent, WalletPubContent, contract, w3)

'''







####################################
#####            PGP           #####
####################################

from os import system
import hashlib

KEYS_PATH = 'PGP'
MESSAGES_PATH = 'Messages'

from os.path import isfile


def genKeypair(path_for_keys):
    system("mkdir " + KEYS_PATH)
    system("mkdir " + MESSAGES_PATH)
    system("openssl genrsa -out ./" + path_for_keys + "/keypair.pem 2048")
    system("openssl rsa -in ./" + path_for_keys + "/keypair.pem -pubout -out ./" + path_for_keys + "/publickey.pem")

def encMessage(msg_path, pub_key_B_path):
    print("openssl rsautl -encrypt -in " + msg_path + " -out " + msg_path + ".enc " + "-inkey " + pub_key_B_path + " -pubin") 
    system("openssl rsautl -encrypt -in " + msg_path + " -out " + msg_path + ".enc " + "-inkey " + pub_key_B_path + " -pubin")
   

def decMessage(msg_path, priv_keypair_A_path):
    print("openssl rsautl -decrypt -in " + msg_path + " -out " + msg_path + ".dec " + "-inkey " + priv_keypair_A_path)
    system("openssl rsautl -decrypt -in " + msg_path + " -out " + msg_path + ".dec " + "-inkey " + priv_keypair_A_path)

def md5(file_path):    
    md5_hash = hashlib.md5()    
    a_file = open(file_path, "rb")
    content = a_file.read()
    md5_hash.update(content)    
    digest = md5_hash.hexdigest()
    return digest

def sign(msg_path, priv_keypair_A_path):
    msg_hash = md5(msg_path)
    md5_file_path = msg_path + ".md5"
    with open(md5_file_path, 'w') as f_output:
            f_output.write(str(msg_hash))
    system("openssl rsautl -sign -in " + md5_file_path + " -out " + md5_file_path + ".sig " + "-inkey ./" + priv_keypair_A_path)
    system(f'''rm {md5_file_path}''')

def vrfSign(msg_dec_path, pub_key_B_path, msg_sig_B_path):
    msg_hash = md5(msg_dec_path)
    #md5_file_path = msg_dec_path + ".md5"
    #with open(md5_file_path, 'w') as f_output:
    #        f_output.write(str(msg_hash))
    print("openssl rsautl -verify -in " + msg_sig_B_path + " -out " + msg_sig_B_path + ".vrf " + "-inkey " + pub_key_B_path + " -pubin")
    system("openssl rsautl -verify -in " + msg_sig_B_path + " -out " + msg_sig_B_path + ".vrf " + "-inkey " + pub_key_B_path + " -pubin")
    # If openssl verify could not create the file .vrf the verification must fail
    print(isfile(msg_sig_B_path + ".vrf"))
    if isfile(msg_sig_B_path + ".vrf") == False:
        return False
    with open(msg_sig_B_path + ".vrf", 'r') as hash_signed:
        msg_hash_calculated = hash_signed.read()
    print(msg_hash_calculated)
    print(msg_hash)
    if msg_hash == msg_hash_calculated:
        return True
    else:
        return False


# Usage:
#genKeypair(KEYS_PATH)
#system("echo 'test message' > ./Messages/test001.txt")

#encMessage('./Messages/test001.txt', './PGP/publickey.pem')
#decMessage('./Messages/test001.txt.enc', './PGP/keypair.pem')


#sign('./Messages/test001.txt', './PGP/keypair.pem')
#result = vrfSign('./Messages/test001.txt.enc.dec', './PGP/publickey.pem', './Messages/test001.txt.md5.sig')
#print(result)















          
##############################################
######## Graphical Interface (TKinter) #######
##############################################
          
import tkinter as tk
from tkinter.filedialog import askopenfilename, asksaveasfilename
from os import getcwd
MSG_PATH = ""
from tkinter import messagebox
from tkinter import simpledialog

def open_file():
    """Open a file for editing."""
    filepath = askopenfilename(initialdir=getcwd() + "/Messages/",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*"), ("Text Files", "*.enc"), ("Text Files", "*.dec")]
    )
    if not filepath:
        return
    global MSG_PATH
    MSG_PATH = filepath
    txt_edit.delete(1.0, tk.END)
    with open(filepath, "r") as input_file:
        text = input_file.read()
        txt_edit.insert(tk.END, text)
    window.title(f"PGP with PKI blockchain-based - {MSG_PATH}")
    
 

def save_file():
    """Save the current file as a new file."""
    filepath = asksaveasfilename(initialdir=getcwd()+"/Messages/",
        defaultextension="txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
    )
    if not filepath:
        return
    with open(filepath, "w") as output_file:
        text = txt_edit.get(1.0, tk.END)
        output_file.write(text)
    global MSG_PATH
    MSG_PATH = filepath
    window.title(f"PGP with PKI blockchain-based - {MSG_PATH}")

    
def close_file():
    window.title("PGP with PKI blockchain-based")
    txt_edit.delete(1.0, tk.END)
    
    
def encryptAndSign():
    filepath = askopenfilename(initialdir=getcwd() + "/Messages/",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*"), ("Text Files", "*.enc")]
    )
    MSG_PATH = filepath
    message_short_path = MSG_PATH.replace(getcwd(), '.')
    destination_pub_key_path = message_short_path + ".DestinationPubKey"
    with open(destination_pub_key_path, "w") as output_file:
        output_file.write(otherMO.publicKey)
    encMessage(message_short_path, destination_pub_key_path)
    system(f'''rm {destination_pub_key_path}''')
    sign(message_short_path, './PGP/keypair.pem')
    

def decrypt():
    filepath = askopenfilename(initialdir=getcwd() + "/Messages/",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*"), ("Text Files", "*.enc")]
    )
    MSG_PATH = filepath
    message_short_path = MSG_PATH.replace(getcwd(), '.')
    print(message_short_path)
    decMessage(message_short_path, './PGP/keypair.pem')
    txt_edit.delete(1.0, tk.END)
    with open(message_short_path + ".dec", "r") as input_file:
        text = input_file.read()
        txt_edit.insert(tk.END, text)
    window.title(f"PGP with PKI blockchain-based - {MSG_PATH}")
    
    origin_pub_key_path = message_short_path + ".OriginPubKey"
    with open(origin_pub_key_path, "w") as output_file:
        output_file.write(otherMO.publicKey)
    verification = vrfSign(message_short_path + ".dec", origin_pub_key_path, message_short_path.replace('.txt.enc', '.txt.md5.sig'))
    if verification:    
        txt_edit.insert(tk.END, f'''\n --- Signature of the sender MO:{otherMO.idNumber} has been verified and is correct --- ''')
    else:
        txt_edit.insert(tk.END, f'''\n --- Signature of the sender MO:{otherMO.idNumber} has been verified and is NOT correct --- ''')
    with open(message_short_path + ".dec", "w") as output_file:
        text = txt_edit.get(1.0, tk.END)
        output_file.write(text)
    

def getMOPKI(MO, text_MO):
    MO.idNumber = entryOfMOId.get()
    MO_on_PKI = getMilitaryOrganization(int(MO.idNumber) , contract)
    MO.name = MO_on_PKI[1]
    MO.publicWallet = MO_on_PKI[2]
    MO.email = MO_on_PKI[3]
    MO.publicKey = MO_on_PKI[4]
    text_MO["text"] = MO.getInfo()
    
def changeId(MO, text_box):
    MO.idNumber = entryOfmyMOId.get()
    MO_on_PKI = getMilitaryOrganization(int(MO.idNumber) , contract)
    MO.name = MO_on_PKI[1]
    MO.publicWallet = MO_on_PKI[2]
    MO.email = MO_on_PKI[3]
    MO.publicKey = MO_on_PKI[4]
    text_box["text"] = MO.getInfo()
    
def updatePGPtoPKI():
    USER_ID = int(simpledialog.askstring(title="ID", prompt="What is your id?"))
    print(USER_ID)
    
    WalletPubFile = open('./Wallet/pub_wallet.txt', "rb")
    WalletPubContent = WalletPubFile.read().decode("utf-8")
    print(WalletPubContent)
    
    WalletPrivFile = open('./Wallet/priv_wallet.txt', "rb")
    WalletPrivContent = WalletPrivFile.read().decode("utf-8")
    print(WalletPrivContent)
    
    PGPpublicKeyFile = open('./PGP/publickey.pem', "rb")
    PGPpublicKeyContent = PGPpublicKeyFile.read().decode("utf-8")
    print(PGPpublicKeyContent)
    
    resetPublicKey(USER_ID, PGPpublicKeyContent, WalletPrivContent, WalletPubContent, contract, w3)
    messagebox.showinfo(title="PKI data updated", message="Your encryption keys will be available on the PKI blockchain soon!")
    #resetAddr(USER_ID, '0xa636B909f8Dc044c7281aad6A87A6C8AfE9B2ba3', priv_key, pub_addr, contract, w3)

def generateNewPGPKeys(KEYS_PATH):
    if isfile("./PGP/keypair.pem") == False:
        messagebox.showinfo(title="New PGP keys", message="New PGP keys were generated to this computer!")
        genKeypair(KEYS_PATH)
        messagebox.showinfo(title="PGP keys generated", message="New encryption keys were generated.")
        updatePGPtoPKI()
    else:
        is_ok = messagebox.askokcancel(title="Caution", message="You already have encryption keys.\nWhen generating new keys, the previous ones will be overwritten.\nDo you want to create new encryption keys?")
        if is_ok:
            genKeypair(KEYS_PATH)
            messagebox.showinfo(title="PGP keys generated", message="New encryption keys were generated.")
            updatePGPtoPKI()
        else:
            messagebox.showinfo(title="PGP keys not generated", message="New encryption keys were not generated, old ones remain valid!")
            
def updatePKIEmail():
    USER_ID = int(simpledialog.askstring(title="ID", prompt="What is your id?"))
    print(USER_ID)
    USER_EMAIL = simpledialog.askstring(title="Email", prompt="What is your email?")
    print(USER_EMAIL)
    
    WalletPubFile = open('./Wallet/pub_wallet.txt', "rb")
    WalletPubContent = WalletPubFile.read().decode("utf-8")
    print(WalletPubContent)
    
    WalletPrivFile = open('./Wallet/priv_wallet.txt', "rb")
    WalletPrivContent = WalletPrivFile.read().decode("utf-8")
    print(WalletPrivContent)
    
    PGPpublicKeyFile = open('./PGP/publickey.pem', "rb")
    PGPpublicKeyContent = PGPpublicKeyFile.read().decode("utf-8")
    print(PGPpublicKeyContent)

    #resetPublicKey(USER_ID, PGPpublicKeyContent, WalletPrivContent, WalletPubContent, contract, w3)
    
    tx_hash = resetEmail(USER_ID, USER_EMAIL, WalletPrivContent, WalletPubContent, contract, w3)
    print(tx_hash)
    #resetPublicKey(USER_ID, PGPpublicKeyContent, WalletPrivContent, WalletPubContent, contract, w3)
    messagebox.showinfo(title="PKI data updated", message="Your email will be available on the PKI blockchain soon!")
    #resetAddr(USER_ID, '0xa636B909f8Dc044c7281aad6A87A6C8AfE9B2ba3', priv_key, pub_addr, contract, w3)

def exitProgram():
    import os
    os._exit(0)
    
def setWallet(priv_wallet, pub_wallet):
    system("cp ./Wallet/priv_wallet.txt ./Wallet/old_priv_wallet.txt")
    system("cp ./Wallet/pub_wallet.txt ./Wallet/old_pub_wallet.txt")
    with open('./Wallet/priv_wallet.txt', 'w') as WalletPrivFile:
        WalletPrivFile.write(str(priv_wallet))
    with open('./Wallet/pub_wallet.txt', 'w') as WalletPubFile:
        WalletPubFile.write(str(pub_wallet))
    
def importNewWallet():
    USER_ID = int(simpledialog.askstring(title="ID", prompt="What is your id?"))
    print(USER_ID)
    USER_PRIV_WALLET = simpledialog.askstring(title="Priv wallet", prompt="What is your Private Wallet key?")
    print(USER_PRIV_WALLET)
    USER_PUB_WALLET = simpledialog.askstring(title="Pub wallet", prompt="What is your Public Wallet key?")
    print(USER_PUB_WALLET)
    setWallet(USER_PRIV_WALLET, USER_PUB_WALLET)
    
    WalletPubFile = open('./Wallet/old_pub_wallet.txt', "rb")
    WalletPubContent = WalletPubFile.read().decode("utf-8")
    print(WalletPubContent)
    
    WalletPrivFile = open('./Wallet/old_priv_wallet.txt', "rb")
    WalletPrivContent = WalletPrivFile.read().decode("utf-8")
    print(WalletPrivContent)
    resetAddr(USER_ID, USER_PUB_WALLET, WalletPrivContent, WalletPubContent, contract, w3)
    
    

class MilitaryOrganization:
    def __init__(self):
        self.idNumber = "----"
        self.name = "----"
        self.email = "----"
        self.privateKey = "----"
        self.publicKey = "----"
        self.privateWallet = "----"
        self.publicWallet = "----"
    
    def getInfo(self):
        text = f'''
        ID: {self.idNumber}
        Name: {self.name}
        Email: {self.email}
        PublicWallet: {self.publicWallet}
        PublicKey: {self.publicKey}
        '''
        return text

myMO_PKI = MilitaryOrganization()
myMO_thisPC = MilitaryOrganization()
otherMO = MilitaryOrganization()

# (TKinter) init loop
window = tk.Tk()
window.title("PGP with PKI blockchain-based")
window.rowconfigure(0, minsize=400, weight=1)
window.columnconfigure(1, minsize=400, weight=1)

######## (TKinter) Left buttons ########
fr_buttons = tk.Frame(window, relief=tk.RAISED, bd=2)

btn_open = tk.Button(fr_buttons, text="Open msg", command=open_file)
btn_save = tk.Button(fr_buttons, text="Save msg", command=save_file)
btn_write = tk.Button(fr_buttons, text="Write msg", command=close_file)
btn_open.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
btn_save.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
btn_write.grid(row=2, column = 0, sticky="ew", padx=5, pady=5)

text_otherMOid = tk.Label(fr_buttons, text="Id Number of the other \nMilitary Organization (MO):")
text_otherMOid.grid(row=3, column = 0, sticky="ew", padx=5, pady=5)
entryOfMOId = tk.Entry(fr_buttons)
entryOfMOId.insert(10, "")
entryOfMOId.grid(row=4, column = 0, sticky="ew", padx=5, pady=5)
btn_otherMOgetPKI = tk.Button(fr_buttons, text="Get MO PKI data", command= lambda: getMOPKI(otherMO, text_otherMOPKIdata))
btn_otherMOgetPKI.grid(row=5, column = 0, sticky="ew", padx=5, pady=10)
text_otherMOPKIdata = tk.Label(fr_buttons, text=otherMO.getInfo())
text_otherMOPKIdata.grid(row=6, column = 0, sticky="ew", padx=5, pady=0)

btn_EncSign = tk.Button(fr_buttons, text="Encryp and Sign", command=encryptAndSign)
btn_Decrypt = tk.Button(fr_buttons, text="Decrypt and Verify", command=decrypt)
btn_ExitProgram = tk.Button(fr_buttons, text="Exit Program", command=exitProgram)
btn_EncSign.grid(row=7, column=0, sticky="ew", padx=5, pady=5)
btn_Decrypt.grid(row=8, column=0, sticky="ew", padx=5, pady=5)
btn_ExitProgram.grid(row=9, column=0, sticky="ew", padx=5, pady=5)



########## (TKinter) Central ###########
txt_edit = tk.Text(window)


####### (TKinter) Right buttons ########
fr_PKIinfo = tk.Frame(window, relief=tk.RAISED, bd=2)

'''
text_MyMO_PKIdata_title = tk.Label(fr_PKIinfo, text="Your MO data on PKI (blockchain):")
text_MyMO_PKIdata_title.grid(row=0, column = 3, sticky="ew", padx=5, pady=5)

text_MyMO_PKIdata = tk.Label(fr_PKIinfo, text=myMO_PKI.getInfo())
text_MyMO_PKIdata.grid(row=1, column=3, sticky="nsew")

text_MyMO_thisPCdata_title = tk.Label(fr_PKIinfo, text="Your MO data on this PC:")
text_MyMO_thisPCdata_title.grid(row=2, column = 3, sticky="ew", padx=5, pady=5)

text_MyMO_thisPCdata = tk.Label(fr_PKIinfo, text=myMO_thisPC.getInfo())
text_MyMO_thisPCdata.grid(row=3, column=3, sticky="nsew")

entryOfmyMOId = tk.Entry(fr_PKIinfo)
entryOfmyMOId.insert(10, "11031")
entryOfmyMOId.grid(row=4, column=3, stick="nsew")

btn_myMOgetPKI = tk.Button(fr_PKIinfo, text="Change ID", command= lambda: changeId(myMO_thisPC, text_MyMO_thisPCdata))
btn_myMOgetPKI.grid(row=5, column=3, stick="nsew")
'''

btn_genNewPGPKeys = tk.Button(fr_PKIinfo, text="Generate PGP keys", command= lambda: generateNewPGPKeys(KEYS_PATH))
btn_genNewPGPKeys.grid(row=6, column=3, stick="nsew")

btn_updatePKIEmail = tk.Button(fr_PKIinfo, text="Update my Email on PKI", command= lambda: updatePKIEmail())
btn_updatePKIEmail.grid(row=7, column=3, stick="nsew")

btn_importNewWallet = tk.Button(fr_PKIinfo, text="Import new Wallet", command= lambda: importNewWallet())
btn_importNewWallet.grid(row=8, column=3, stick="nsew")


# (TKinter) finalize loop
fr_buttons.grid(row=0, column=0, sticky="ns")
txt_edit.grid(row=0, column=1, sticky="ew")
fr_PKIinfo.grid(row=0, column=2, sticky="nsew")

window.mainloop()









































