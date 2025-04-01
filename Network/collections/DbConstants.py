import sys

VERSION = '2.4'

DEFL_DOMAIN = 500
DEFL_SET_SIZE = 50
DEFL_PORT = 5001

DEFL_KEYSIZE_PAILLIER = 2048
DEFL_KEYSIZE_DAMGARD = 2048
DEFL_EXPANSIONFACTOR = 2

TEST_ROUNDS = 20  # This would be 20 * 6 type of operations, so 120 operations in total

FB_URL = 'https://ws-psi-default-rtdb.europe-west1.firebasedatabase.app/'


def print_banner():
    banner = f"""
###############################################################
#                                                             #
#,------.  ,---.  ,--.     ,---.          ,--.  ,--.          #
#|  .--. ''   .-' |  |    '   .-' ,--.,--.`--',-'  '-. ,---.  #
#|  '--' |`.  `-. |  |    `.  `-. |  ||  |,--.'-.  .-'| .-. : #
#|  | --' .-'    ||  |    .-'    |'  ''  '|  |  |  |  \   --. #
#`--'     `-----' `--'    `-----'  `----' `--'  `--'   `----' #
#                                                             #
###############################################################
#           PSI Suite - Web Service - Flask API and Interface #
#           Author: Santiago Arias - github.com/4rius/WS_PSI  #
#           VERSION: {VERSION}                                      #
###############################################################
    """
    print(banner)
