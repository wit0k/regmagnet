# The code taken from: https://github.com/DidierStevens/DidierStevensSuite/blob/master/base64dump.py

import binascii
import re


def _b64_dump(data):

    base64string = ""
    for base64string in re.findall('[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/]+={0,2}', data, re.IGNORECASE + re.MULTILINE):
            if len(base64string) % 4 == 0:

                if len(base64string) > 16:
                        try:
                            result_bytes = binascii.a2b_base64(base64string)
                            result_str = result_bytes.decode()
                            yield result_str
                        except:

                            if base64string.endswith('='):
                                result_str = result_bytes.decode('utf8', 'ignore')
                                yield result_str
                            elif len(base64string) > 260:  # Bigger than MAX_PATH_LEN
                                result_str = result_bytes.decode('utf8', 'ignore')
                                yield result_str

                            continue

    return data

