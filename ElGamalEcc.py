# -*- coding: utf-8 -*-
"""
Created on Fri Dec 10 11:43:28 2021

El-Gamal Digital Signature on Elliptic Curve (EC)

Creates digital signature for a message using El-Gamal
algorithm, calculations based on ECC.

@author: Ayala Cohen
"""

from tinyec.ec import SubGroup, Curve, Point, mod_inv, Inf
import hashlib
import binascii
from random import randrange
"""
El-Gamal on ECC. Holds function for computing & verifying digital signatures.
Parameter values n, G, a, b taken from ANSInet paper.
"""
class ElGamalEcc:
    
    prKey=0       # private key (Alice's or Bob's. Depends on who 
                  # this class is an instance of)
    myPublicK=0             # Alice's public key
    othersPublicK=0         # Bob's public key
    
    """
    Create field with given parameters:
        G (generator) = (5,7)
        p (Fp - field over prime p) = 29
        n (prime order) = 31
    """
    field = SubGroup(p=29, g=(5, 7), n=31, h=1) # G = {5, 7}, which has order of 31
    
    """
    Create Elliptic Curve y2 ≡ x3 - x + 16 (mod 29), over given field (above).
    Curve Parameters:
        a = -1
        b = 16
    """
    curve = Curve(a=-1, b=16, field=field, name='p1707') # y2 ≡ x3 - x + 16 (mod 29)
    G = curve.g                     # set G=(5,7) - generator of curve
    n = 31  # THIS IS P!                         
    
    def __init__(self, prKey): # class constructor
        """
        Private Key must be in range [1,n-1]    
        """
        if prKey < 1 or prKey > self.n:
            print("Invalid private key for El-Gamal! Key must be in range [1,",self.n,"-1]")
            return
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
        """ Alice signs the message m:
            1. Create a hash of the message e=HASH(m)
            Our hash function in SHA-256.
            """
        e = str(hashlib.sha256(m.encode('utf-8')).hexdigest())
        
        e = str(bin(int(e, 16))) # Convert from hex to binary
        """
        2. Let z be n leftmost bits of e (n=31 in our case)
        """
        z = e[0:self.n]
        z = int(z, 16)  # Convert from binary to hex
        while(True):
            """
            3. Create a random number k which is between 1 and n-1 (30)
            """
            k = randrange(self.n-1)
            """
            4. Calculate a point on the curve as (x1,y1)=k X G
            """
            point = k * self.G
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
        7. The signature is the pair (R,s) (Point=R)
        """
        return point, s

    def verifyDigitalSignature(self, m, r, s):
        """
        Verify that s is an integer in [1,n-1] and R is an element in E(F_p=F_29)
        """
        if s < 1 or s > self.n or not self.curve.on_curve(r.x,r.y):
            return False
        """
        Bob will check the digital signature:
        1. Create a hash of the message e=HASH(m)
        """
        e = str(hashlib.sha256(m.encode('utf-8')).hexdigest())
        e = str(bin(int(e, 16))) # Convert from hex to binary
        """
        2. z will be the n leftmost bits of e (n=31)
        """
        z = e[0:self.n]
        z = int(z, 16)
        
        """
        3. Compute V1 = sR
        """
        V1 = s*r
        
        """
        4. Compute V2 = H(M)G+rA (where r= [x coordinate of R])
        """
        V2 =z*self.G + r.x*self.othersPublicK
        """ Accept iff V1 = V2 """
        if (V1 == V2): 
            return True
        return False
