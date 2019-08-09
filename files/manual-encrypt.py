#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Edin Mujkanovic, Taesuk Joung, Victor Truan"
__license__ 	= "GPL"
__version__ 	= "1.0"
__status__ 		= "Prototype"

from scapy.all import *
import rc4
import zlib

# wep key AA:AA:AA:AA:AA
key = '\xaa\xaa\xaa\xaa\xaa'

# We read the original encrypted message from the wireshark file - rdpcap always returns an array,
# even if the pcap only contains one frame
arp = rdpcap('arp.cap')[0]

# We create a new message.
message = "Encrypt me please"
# We use CRC-32 to calculate the ICV and we cast it in unsigned long
# Thank to Filipe Fortunato to show us that the result of the crc32 function was too long.
icvMessage = zlib.crc32(message) & 0xffffffff
# We generate the full "Payload"
payload = message+struct.pack('<L', icvMessage)
# We kept the old way to calculate the seed.
seed = arp.iv+key 

# Now we need to encrypt the payload, the cipherText contains crypted Data + icv
cipherText = rc4.rc4crypt(payload, seed)
# We kept the hex format.
print 'Message to encrypt :' + message + ' with the ICV ' +'{:x}'.format(icvMessage)
print 'Encrypted message : ' + cipherText[:-4] + ' and the encrypted ICV is ' + cipherText[-4:]

# We change the data in the frame so it contains our new ciphered data.
arp.wepdata = cipherText[:-4]

# We change the ICV too.
arp.icv = struct.unpack('!L', cipherText[-4:])[0]

# We are writing the pcap file name openme.pcap
# This file contains the data "Encrypt me please" and can be opened with wireshark if
# the configuration is correct.
wrpcap("openme.pcap", arp)