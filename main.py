from utils.nxosrest import NexusREST
from utils.logger import logger
import os
import requests


if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings()

    try:
        IP = os.environ['SWITCH_IP']
        username = os.environ['SWITCH_USER']
        password = os.environ['SWITCH_PASSWORD']
    except KeyError:
        logger.error('Switch ENV Variables Not Found. Exiting...')
        exit(1)

    switch = NexusREST(IP, username, password)
    switch.login()

    print(switch.get_svi())
    print(switch.get_bd())
    print(switch.get_vrfs())

    switch.logout()
