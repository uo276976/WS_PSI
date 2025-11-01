import sys

VERSION = '3.0'

DEFL_DOMAIN = 500
DEFL_SET_SIZE = 50
DEFL_PORT = 5001

DEFL_KEYSIZE_PAILLIER = 2048
DEFL_KEYSIZE_DAMGARD = 2048
DEFL_EXPANSIONFACTOR = 2

TEST_ROUNDS = 20  # This would be 20 * 6 type of operations, so 120 operations in total

FB_URL = 'https://ws-psi-default-rtdb.europe-west1.firebasedatabase.app/'


def print_banner():
    version_str = f"VERSION: {VERSION}"
    version_line = f"#     {version_str:<55}#"

    banner = f"""
###############################################################
#                                                             #
#,------.  ,---.  ,--.     ,---.          ,--.  ,--.          #
#|  .--. ''   .-' |  |    '   .-' ,--.,--.`--',-'  '-. ,---.  #
#|  '--' |`.  `-. |  |    `.  `-. |  ||  |,--.'-.  .-'| .-. : #
#|  | --' .-'    ||  |    .-'    |'  ''  '|  |  |  |  \\   --.#
#`--'     `-----' `--'    `-----'  `----' `--'  `--'   `----' #
#                                                             #
###############################################################
#     PSI Suite - Web Service - Flask API and Interface       #
#     Authors: Santiago Arias - github.com/4rius/WS_PSI,      #
#        Alfonso González-Lamuño - github.com/uo276976/WS_PSI #
{version_line}
###############################################################
    """
    print(banner)
