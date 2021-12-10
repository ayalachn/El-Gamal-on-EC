# -*- coding: utf-8 -*-
"""
Created on Fri Dec 10 11:43:28 2021

El-Gamal Digitial Signature on Elliptic Curve (EC)

Creates digital signature for a message using El-Gamal
algorithm, calculations based on ECC.

@author: Ayala Cohen
"""

# import ECC
from tinyec.ec import SubGroup, Curve, Point, mod_inv, Inf
import hashlib
import binascii
from random import randrange
class ElGamalEcc:
    
    prKey=0       # private key (Alice's or Bob's. Depends on who 
                  # this class is an instance of)
    myPublicK=0             # Alice's public key
    othersPublicK=0         # Bob's public key
    field = SubGroup(p=17, g=(15, 13), n=18, h=1) # G = {15, 13}, which has order of n = 18
    curve = Curve(a=0, b=7, field=field, name='p1707') # y2 ≡ x3 + 7 (mod 17)
    G = curve.g                     # G=(15,13)
    n = 17
    
    def __init__(self, prKey): # class constructor
        self.prKey = prKey
        """
        Calculate public key using the formula:
            pubKey = privKey X G
          Where X denotes multiplication under ECC.   
        """  
        self.myPublicK= prKey * self.G
    
    def setOthersPublicKey(self, othersPublicKey):
        self.othersPublicK=othersPublicKey
    
    def getMyPublicKey(self):
        return self.myPublicK
    
    def digitalSignMessage(self, m):
        """ Alice signs the message:
            1. Create a hash of the message e=HASH(m)
            """
        e = str(hashlib.sha256(m.encode('utf-8')).hexdigest())
        print("sha256 hash:\n", e)
        """
        2. Let z be n leftmost bits of e (n=17 in our case)
        """
        z = e[0:self.n]
        print("z:\n", z)
        z = int(z, 16)
        while(True):
            """
            3. Create a random number k which is between 1 and n-1 (16)
            """
            k = randrange(16)
            print("k=",k)
            """
            4. Calculate a point of the curve as (x1,y1)=k X G
            """
            point = k * self.G
            print("point: ", point)
            """
            5. Calculate r=x1 % n. If r=0, go back to step 3.
            """
            r = int(point.x) % self.n

            """
            6. Calculate s = k^-1 (z + r*dA) % n. If s=0 go back to step 3.
            """
            inv_k = mod_inv(k, self.n) # inverse of k
            s = inv_k * (z + r * self.prKey) % self.n
            if r != 0 and s!=0:
                break
        
        """ 
        7. The signature is the pair (r,s)
        """
        
        return r, s

    def verifyDigitalSignature(self, m, r, s):
        """
        Bob will check the digital signature:
        1. Create a hash of the message e=HASH(m)
        """
        e = str(hashlib.sha256(m.encode('utf-8')).hexdigest())
        print("sha256 hash:\n", e)
        
        """
        2. z will be the n leftmost bits of e (n=17)
        """
        z = e[0:self.n]
        print("z:\n", z)
        z = int(z, 16)
        
        """
        3. Calculate c=s^-1 mod n
        """
        inv_s = mod_inv(s, self.n) # inverse of s
        c = inv_s % self.n
        """
        4. Calculate:
            u1 = z*c mod n
            u2 = r*c mod n
        """
        u1 = z*c % self.n
        u2 = r*c % self.n
        
        """
        5. Calculate the curve point:
            (x1, y1) = u1 X G + u2 X pubK_A.
            If (x1,y1)=O then the signature is invalid.
        """
        point = u1*self.G + u2*self.othersPublicK
        if point == Inf(curve=self.curve):
            print("Signature is invalid. Line 121")
            return False
        """
        6. The signature is valid if r=x1 mod n. Invalid otherwise
        """    
        if r != point.x % self.n:
            print("Signature is valid.")
            return True
        else:
            print("Signature is invalid. Line 130")
            return False

bob = ElGamalEcc(7)
alice = ElGamalEcc(3)      
 
print("==== SIGN MESSAGE ====")  
alice.setOthersPublicKey(bob.getMyPublicKey())
msg="Hello"   
r,s = alice.digitalSignMessage(msg)
print("r=",r," s=",s)

print("==== VERIFY MESSAGE ====")  
bob.setOthersPublicKey(alice.getMyPublicKey()) 
print(bob.verifyDigitalSignature(m=msg, r=r, s=s))
