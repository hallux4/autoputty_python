#!/usr/bin/env python
# coding=utf-8

import untangle
from Crypto.Cipher import DES3
import base64
import md5
import getpass


class Host(object):

    def __init__(self, HostEntry, HostName, User, Password, Type):
        self.HostEntry = HostEntry
        self.HostName = HostName
        self.User = User
        self.Password = Password
        self.Type = Type

    def printHost(self):
        print('Host ' + self.HostEntry.encode("utf-8"))
        print('    HostName ' + self.HostName.encode("utf-8"))
        print('    User ' + self.User.encode("utf-8"))
        print('    Password ' + self.Password.encode("utf-8"))
        print('    Type ' + self.Type)


class EncryptionCentral(object):

    CIPHER = None
    BS = DES3.block_size

    def __init__(self):
        self.init_cipher()

    def pad(self, s):
        padding = self.BS - len(s) % self.BS
        return s + padding * chr(padding)

    def unpad(self, s):
        return s[0:-ord(s[-1])]

    def init_cipher(self):
        m = md5.new()
        password = getpass.getpass()
        m.update(password)

        key = m.digest()
        self.CIPHER = DES3.new(key, DES3.MODE_ECB)

    def encrypt_string(self, string_toencrypt):
        string_toencrypt = self.pad(string_toencrypt)
        return base64.b64encode(self.CIPHER.encrypt(string_toencrypt))

    def decrypt_string(self, encrypted_string):
        return self.unpad(unicode(self.CIPHER.decrypt(
                        base64.b64decode(encrypted_string)), "utf-8"))

    def decrypt_xml(self):
        o = untangle.parse('autoputty.xml')

        for neighbor in o.List.Server:
            print ''
            VHostEntry = neighbor['Name']
            if hasattr(neighbor, 'Host'):
                VHostName = self.decrypt_string(neighbor.Host.cdata)
            if hasattr(neighbor, 'User'):
                VUser = self.decrypt_string(neighbor.User.cdata)
            if hasattr(neighbor, 'Password'):
                VPassword = self.decrypt_string(neighbor.Password.cdata)
            if hasattr(neighbor, 'Type'):
                VType = neighbor.Type.cdata
            toto = Host(VHostEntry, VHostName, VUser, VPassword, VType)
            toto.printHost()

# print EncryptionCentral().encrypt_string('root')
# print EncryptionCentral().decrypt_string(
#                            EncryptionCentral().encrypt_string('root'))


EncryptionCentral().decrypt_xml()
# print EncryptionCentral().encrypt_string('root')
