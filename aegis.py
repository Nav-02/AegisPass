import os
import json
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class Aegis:
    def __init__(self):
        self.saltSize = 16
        self.iterationCount = 600000

    def deriveKey(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterationCount,
        )
        return kdf.derive(password.encode('utf-8'))

    def create_new_vault(self, masterPassword, answers):
        dek = AESGCM.generate_key(bit_length=256)

        userSecret = masterPassword + "".join(answers)
        recoveryKeyString = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
        saltUser = os.urandom(self.saltSize)
        kekUser = self.deriveKey(userSecret, saltUser)
        aesUser = AESGCM(kekUser)
        nonceUser = os.urandom(12)
        wrappedDekUser = aesUser.encrypt(nonceUser, dek, None)
        saltRecovery = os.urandom(self.saltSize)
        kekRecovery = self.deriveKey(recoveryKeyString, saltRecovery)
        aesRecovery = AESGCM(kekRecovery)
        nonceRecovery = os.urandom(12)
        wrappedDekRecovery = aesRecovery.encrypt(nonceRecovery, dek, None)
        aesDek = AESGCM(dek)
        vaultNonce = os.urandom(12)
        encryptedVault = aesDek.encrypt(vaultNonce, json.dumps([]).encode('utf-8'), None)
        slotUserFinal = {
            "salt": base64.b64encode(saltUser).decode('utf-8'),
            "nonce": base64.b64encode(nonceUser).decode('utf-8'),
            "ciphertext": base64.b64encode(wrappedDekUser).decode('utf-8')
        }
        slotRecoveryFinal = {
            "salt": base64.b64encode(saltRecovery).decode('utf-8'),
            "nonce": base64.b64encode(nonceRecovery).decode('utf-8'),
            "ciphertext": base64.b64encode(wrappedDekRecovery).decode('utf-8')
        }
        finalStructure = {
            "version": 1,
            "slot_user": slotUserFinal,
            "slot_recovery": slotRecoveryFinal,
            "data": {
                "nonce": base64.b64encode(vaultNonce).decode('utf-8'),
                "ciphertext": base64.b64encode(encryptedVault).decode('utf-8')
            }
        }
        return finalStructure, recoveryKeyString

    def unlock_vault(self, vaultData, password=None, answers=None, recoveryKey=None):
        try:
            dek = None
            if recoveryKey:
                slot = vaultData["slot_recovery"]
                secret = recoveryKey
            else:
                slot = vaultData["slot_user"]
                secret = password + "".join(answers)
            salt = base64.b64decode(slot["salt"])
            nonce = base64.b64decode(slot["nonce"])
            ciphertext = base64.b64decode(slot["ciphertext"])
            kek = self.deriveKey(secret, salt)
            dek = AESGCM(kek).decrypt(nonce, ciphertext, None)
            dataBlock = vaultData["data"]
            dataNonce = base64.b64decode(dataBlock["nonce"])
            dataCiphertext = base64.b64decode(dataBlock["ciphertext"])
            plaintextBytes = AESGCM(dek).decrypt(dataNonce, dataCiphertext, None)
            return json.loads(plaintextBytes.decode('utf-8')), dek
        except InvalidTag:
            raise ValueError("Invalid credentials.")
    
    def encrypt_for_save(self, vaultList, dek, originalStructure):
        aesDek = AESGCM(dek)
        newNonce = os.urandom(12)
        newCiphertext = aesDek.encrypt(newNonce, json.dumps(vaultList).encode('utf-8'), None)
        newStructure = originalStructure.copy()
        newStructure["data"] = {
            "nonce": base64.b64encode(newNonce).decode('utf-8'),
            "ciphertext": base64.b64encode(newCiphertext).decode('utf-8')
        }
        return newStructure