import base64
import logging
import types
import re
import collections

import string
import sys
import math
import gzip

from os.path import isfile

from itertools import cycle

from Crypto.Cipher import AES

from handlers.vbe import _decode_vbe
from handlers.base64 import _b64_dump

from urllib.parse import unquote_plus

import sys, hexdump, binascii
from Crypto.Cipher import AES

logger = logging.getLogger('regmagnet')

class handlers(object):

    test = ""

    def __init__(self):
        pass

    def get_handlers_help():

        reg_handlers = {}
        for _attribute in handlers.__dict__.items():
            #if isinstance(_attribute[1], types.FunctionType):
            if isinstance(_attribute[1], type):
                if not True in [_attribute[0].startswith(prefix) for prefix in ['get_handlers_help', '__name__', '<', 'md.reg_handlers', 'None', '_']]:

                    func_description = None
                    if hasattr(_attribute[1], 'decription'):
                        func_description = getattr(_attribute[1], 'decription')

                    reg_handlers[_attribute[0]] = func_description

        return reg_handlers


    class decrypt_teamviewer:

        unpad = lambda s: s[0:-ord(s[-1])]

        decription = 'aes_cbc() -> Decrypt data with aes-cbc ... beta'

        def decrypt_teamviewer(input_data):

            if isinstance(input_data, bytes):
                key = binascii.unhexlify("0602000000a400005253413100040000")
                iv = binascii.unhexlify("0100010067244F436E6762F25EA8D704")

                cipher = AES.new(key, AES.MODE_CBC, iv)

                decrypted = cipher.decrypt(input_data)
                decrypted_unpadded = decrypted.decode()

                REGEX_STANDARD = '[\x09\x20-\x7E]'
                regex = '((' + REGEX_STANDARD + '\x00){%d,})'
                decrypted_unpadded = [foundunicodestring.replace('\x00', '') for foundunicodestring, dummy in
                          re.findall(regex % 4, decrypted_unpadded)]

                return ''.join(decrypted_unpadded)
            else:
                return input_data

    class dump_to_file:

        decription = 'dump_to_file() -> Saves the input data buffer to a file specified by a parameter'

        def dump_to_file(input_data, output='dump_to_file.bin'):

            if isinstance(input_data, bytes):
                mode = 'wb'
            elif isinstance(input_data, str):
                mode = 'w'

            loop = True
            index = 0

            while loop:

                new_output = f'{index}-' + output

                if isfile(new_output):
                    index += 1
                else:
                    loop = False

            with open(new_output, mode) as file:
                file.write(input_data)

            return input_data

    class decompress_gzip():

        decription = 'decompress_gzip() -> Attempts to un-gzip the input data'

        def decompress_gzip(input_data):

            """
            GZIP Header:

              0      2 bytes  magic header  0x1f, 0x8b (\037 \213)
              2      1 byte   compression method
                         00: store (copied)
                         01: compress
                         02: pack
                         03: lzh
                         04..7: reserved
                         08: deflate
            """
            decompressed = None

            if isinstance(input_data, str):
                data = input_data.encode()
            else:
                data = input_data

            try:
                decompressed = gzip.decompress(data)
                return decompressed
            except Exception as msg:
                pass

            return input_data

    # https://gist.github.com/Demonslay335/8faaa57891318aa438db4bff10b347df
    # - I made small changes to adopt it to python 3
    class decrypt_rc4():

        decription = 'decrypt_rc4(Key) -> Decrypts the input data with a string key specified'

        # https://github.com/bozhu/RC4-Python
        # RC4 key scheduling
        def KSA(key):
            keylength = len(key)

            S = list(range(0, 256))

            j = 0
            for i in range(0, 256):
                j = (j + S[i] + key[i % keylength]) % 256
                S[i], S[j] = S[j], S[i]  # swap

            return S

        # RC4 pseudo-random generator algorithm
        def PRGA(S):
            i = 0
            j = 0
            while True:
                i = (i + 1) % 256
                j = (j + S[i]) % 256
                S[i], S[j] = S[j], S[i]  # swap

                K = S[(S[i] + S[j]) % 256]
                yield K

        # Use RC4 algorithm
        def RC4(key):
            S = handlers.decrypt_rc4.KSA(key)
            return handlers.decrypt_rc4.PRGA(S)

        # Decrypt using RC4
        def decrypt_rc4(data, key):
            """ Decrypt RC4 encrypted bytes or string """

            return_bytes = None

            if isinstance(data, str):
                cipher_bytes = handlers.decrypt_rc4.convert(data)
                return_bytes = False
                decrypted_data = ''
            else:
                cipher_bytes = data
                return_bytes = True
                decrypted_data = []

            #  Convert the key string to list of ints
            key = handlers.decrypt_rc4.convert(key)

            #  Generate the keystream
            keystream = handlers.decrypt_rc4.RC4(key)

            # Plaintext
            plaintext = ''

            # Decrypt with RC4
            for c in cipher_bytes:
                if isinstance(c, str):
                    x = ord(c) ^ next(keystream)
                else:
                    x = c ^ next(keystream)

                if return_bytes:
                    decrypted_data.append(x)
                else:
                    decrypted_data += chr(x)

            if return_bytes:
                return bytes(decrypted_data)
            else:
                return decrypted_data

        # Convert string to integers
        def convert(s):
            return [ord(c) for c in s]

        # Check for non-ASCII in string
        def ascii_only(s):
            return all(ord(char) < 128 for char in s)

    #  https://stackoverflow.com/questions/20557999/xor-python-text-encryption-decryption
    class sxor:

        decription = 'sxor(Key) -> XOR the input data with a string key specified'

        def sxor(data, key):
            cryptedMessage = ''.join(chr(ord(c)^ord(k)) for c,k in zip(data, cycle(key)))
            return cryptedMessage

    class str:

        decription = 'str() -> Converts the input data to String'

        def str(input_data):

            if not isinstance(input_data, str):
                input_data = str(input_data)
                return input_data

            return input_data

    class shexdump:

        #  https://raw.githubusercontent.com/ActiveState/code/master/recipes/Python/142812_Hex_dumper/recipe-142812.py
        decription = 'str2hex(input_data) -> Converts the input data to HexDump string format'

        def shexdump(input_data, length=8):

            if input_data and isinstance(input_data, str):
                src = input_data
                N = 0;
                result = '\n'
                FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
                while src:
                    s, src = src[:length], src[length:]
                    hexa = ' '.join(["%02X" % ord(x) for x in s])
                    s = s.translate(FILTER)
                    result += "%04X   %-*s   %s\n" % (N, length * 3, hexa, s)
                    N += length
                return result
            else:
                return input_data

    class unescape_url:

        decription = 'unescape_url -> Unescapes the input data string/url'

        def unescape_url(input_data):

            if input_data:
                if isinstance(input_data, str):
                    input_data = unquote_plus(input_data)
                    input_data.replace(r'%20', r' ')

                return input_data

            return input_data

    class cit_dump:

        decription = 'cit_dump() -> Dumps the unicode string and converts it to human readable format (Used for strings originating from cit plugin)'

        def cit_dump(input_data):

            input_data = input_data.decode('utf-16le', 'ignore')

            strings = re.findall("[^\x00-\x1F\x7F-\xFF]{4,}", input_data)

            strings = [string for string in strings if '\\' in string]
            input_data = '"' + ';'.join(strings) + '"'
            # input_data = input_data.encode("unicode_escape").decode("utf-8")

            return input_data

    class utf8_dump:

        decription = 'utf8_dump() -> Dumps the unicode string and converts it to human readable format'

        def utf8_dump(input_data):

            if not isinstance(input_data, str):
                """
                        - Fix the issue with printing results from the plugin:

                        The code causing the issue from python registry:
                            if self.has_ascii_name():
                                return unpacked_string.decode("windows-1252")
                            return unpacked_string.decode("utf-16le")

                        Windows prints the utf-16le but not the Mac!
                        """
                input_data = str(input_data)

            REGEX_STANDARD = '[\x09\x20-\x7E]'
            regex = '((' + REGEX_STANDARD + '\x00){%d,})'
            result =  [foundunicodestring.replace('\x00', '') for foundunicodestring, dummy in
                        re.findall(regex % 4, input_data)]

            return result

            return input_data

    class rslice:

        decription = 'slice(start) -> Slice the input data [Range: start:]'

        def rslice(data, start):

            if isinstance(data, str):
                start = int(start)
                if start <= len(data):
                    return data[start:]
                else:
                    return data

            return data

    class slice:

        decription = 'slice(0, stop) -> Slice the input data [Range: 0:stop]'

        def slice(data, stop):

            if isinstance(data, str):
                stop = int(stop)
                if stop <= len(data):
                    return data[0:stop]
                else:
                    return data

            return data

    class b64_dump:

        decription = 'Dump and decode base64 strings from the input data'
        def b64_dump(input_data) -> str:

            if isinstance(input_data, str):
                _result = _b64_dump(input_data)
                _result = list(_result)
                if _result and _result is not []:
                    return " | ".join(_result)
                else:
                    return input_data

            else:
                return input_data

    class b64_decode:

        decription = 'Decode the input data as base64 string'

        def b64_decode(input_data) -> str:

            try:
                input_data = base64.b64decode(input_data)
            except Exception as msg:
                logger.error('b64decode: Unable to decode input_data. Error: %s. Data: %s' % (msg, input_data))
                return input_data

            return input_data.decode()

    class b64_encode:

        decription = 'Encode the input data to base64 string'

        def b64_encode(input_data) -> str:

            try:
                if isinstance(input_data, str):
                    input_data = base64.b64encode(input_data.encode())
                elif isinstance(input_data, bytes):
                    input_data = base64.b64encode(input_data)
            except Exception as msg:
                logger.error('b64decode: Unable to decode input_data. Error: %s. Data: %s' % (msg, input_data))
                return input_data

            return input_data.decode()

    class decode_vbe:

        decription = 'Attempts to VBE decrypt the input data'

        def decode_vbe(data) ->str:

            if isinstance(data, str):
                return _decode_vbe(data)

    class nothing:

        decription = 'Do nothing, reserved for plugin developers...(Mainly used when only custom handler is required)'

        def nothing(data):

            return data

    class entropy:

        decription = 'entropy() -> Calculates the entropy of the input data'

        def entropy(data):  # Faster version
            e = 0

            counter = collections.Counter(data)
            l = len(data)
            for count in counter.values():
                # count is always > 0
                p_x = count / l
                e += - p_x * math.log2(p_x)

            return e

        #  Functions taken from: https://github.com/DidierStevens/DidierStevensSuite/blob/2a7f11d5f75ded45b7312e547b34be156c762e1d/strings.py
        def C2IIP2(data):
            if sys.version_info[0] > 2:
                return data
            else:
                return ord(data)

        #  Functions taken from: https://github.com/DidierStevens/DidierStevensSuite/blob/2a7f11d5f75ded45b7312e547b34be156c762e1d/strings.py
        def entropy_old(data, dPrevalence=None):

            if isinstance(data, bytes):
                averageConsecutiveByteDifference = None
                if dPrevalence == None:
                    dPrevalence = {iter: 0 for iter in range(0x100)}
                    sumDifferences = 0.0
                    previous = None
                    if len(data) > 1:
                        for byte in data:
                            byte = handlers.entropy.C2IIP2(byte)
                            dPrevalence[byte] += 1
                            if previous != None:
                                sumDifferences += abs(byte - previous)
                            previous = byte
                        averageConsecutiveByteDifference = sumDifferences / float(len(data) - 1)

                sumValues = sum(dPrevalence.values())

                entropy = 0.0
                for iter in range(0x100):
                    if dPrevalence[iter] > 0:
                        prevalence = float(dPrevalence[iter]) / float(sumValues)
                        entropy += - prevalence * math.log(prevalence, 2)

                return entropy
            return data

