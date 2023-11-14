import time
import requests
import json
import threading
from utils.logger import logger


class LoginRefresher(threading.Thread):
    def __init__(self, switch):
        super().__init__()
        self._switch = switch
        self._exit = False

    def run(self) -> None:
        logger.debug('Started Token Refresher Thread')
        while not self._exit:
            time.sleep(self._switch.refresh_token_timeout/2)
            self._switch.refresh_token()

    def exit(self) -> None:
        self._exit = True


class NexusREST:
    """ NexusREST Class """
    def __init__(self, ip, user, pwd):
        self.ip = ip
        self.user = user
        self.pwd = pwd
        self._session = requests.session()
        self.refresh_token_timeout = 600
        self.login_thread = LoginRefresher(self)
        self.token = None
        self.is_authenticated = False

    def get(self, url: str):
        """ HTTP GET from Switch. Users requests.Session cookies"""
        logger.debug(f'HTTP GET https://{self.ip}/api{url}')
        try:
            r = self._session.get(f'https://{self.ip}/api{url}', verify=False, timeout=10)
            logger.debug(f' HTTP Status Code: {r.status_code}, HTTP Response: {r.text}')
            if r.status_code != 200:
                r.raise_for_status()
            else:
                return r
        except requests.exceptions.Timeout as e:
            logger.error(f'Connection Timeout. Error: {e}')
            return
        except requests.HTTPError as e:
            logger.error(f'HTTP Error: {e}')
            return

    def post(self, url: str, data=''):
        """ HTTP Post to Switch. Users requests.Session cookies"""
        logger.debug(f'HTTP POST https://{self.ip}/api{url} with DATA: {data}')
        try:
            r = self._session.post(f'https://{self.ip}/api{url}', data=data, verify=False, timeout=10)
            logger.debug(f' HTTP Status Code: {r.status_code}, HTTP Response: {r.text}')
            if r.status_code != 200:
                r.raise_for_status()
            else:
                return r
        except requests.exceptions.ConnectTimeout as e:
            logger.error(f'Connection Timeout. Error: {e}')
            return
        except requests.HTTPError as e:
            logger.error(f'HTTP Error: {e}')
            return

    def get_bd(self):
        url = '/node/class/l2BD.json?rsp-subtree=full&rsp-prop-include=set-config-only'
        bd_dict = dict()
        r = self.get(url)
        if r is None:
            return
        bd_list = r.json()['imdata']
        for bd in bd_list:
            bd_id = bd['l2BD']['attributes']['id']
            if bd_id == '1':
                continue
            bd_name = bd['l2BD']['attributes']['name']
            bd_encap = bd['l2BD']['attributes']['accEncap']
            bd_dict[bd_id] = {'name': bd_name, 'encap': bd_encap}
        return bd_dict

# switch info /api/mo/sys.json
# switch full conf : /api/mo/sys.json?rsp-subtree=full&rsp-prop-include=set-config-only

    def get_svi(self):
        url = '/node/class/sviIf.json?rsp-subtree=full&rsp-prop-include=set-config-only'
        svi_dict = dict()
        r = self.get(url)
        if r is None:
            return
        svi_list = r.json()['imdata']
        for svi in svi_list:
            svi_descr = ''
            svi_id = svi['sviIf']['attributes']['vlanId']
            if svi_id == '1':
                continue
            if 'descr' in svi['sviIf']['attributes']:
                svi_descr = svi['sviIf']['attributes']['descr']
            svi_vrf = svi['sviIf']['children'][0]['nwRtVrfMbr']['attributes']['tDn']
            svi_dict[svi_id] = {'descr': svi_descr, 'vrf': svi_vrf.split('-')[1]}
        return svi_dict

    def get_vrfs(self):
        """

        :return: dict of vrfs: key = name, {rd:'', encap:''}
        """
        url = '/node/class/l3Inst.json?rsp-subtree=full&rsp-prop-include=set-config-only'
        # url = '/mo/sys.json?query-target=children&target-subtree-class=l3Inst&rsp-subtree=full'
        vrf_dict = dict()
        r = self.get(url)
        if r is None:
            return
        vrf_list = r.json()['imdata']
        for vrf in vrf_list:
            vrf_name = vrf['l3Inst']['attributes']['name']
            if vrf_name in ['management', 'default']:
                continue
            vrf_encap = vrf['l3Inst']['attributes']['encap']
            vrf_descr = vrf['l3Inst']['attributes']['descr']
            vrf_dict[vrf_name] = {'descr': vrf_descr, 'encap': vrf_encap}
        return vrf_dict

    def login(self) -> None:
        """ Login into the Switch. Get Token"""
        url = '/aaaLogin.json'
        auth_body = {"aaaUser": {"attributes": {"name": self.user, "pwd": self.pwd}}}
        post_data = json.dumps(auth_body)
        logger.info(f'logging into {self.ip}')
        r = self.post(url, post_data)
        if r is None:
            logger.error(f'Could not login')
            return
        if r.ok:
            cookie_jar = self._session.cookies.get_dict()
            logger.debug(f'Cookie Jar: {cookie_jar}')
            self.token = cookie_jar['APIC-cookie']
            token_refresh = r.json()['imdata'][0]['aaaLogin']['attributes']['refreshTimeoutSeconds']
            self.refresh_token_timeout = int(token_refresh)
            self.is_authenticated = True
            active_threads = threading.enumerate()
            if self.login_thread not in active_threads:
                self.login_thread.daemon = True
                self.login_thread.start()

    def refresh_token(self) -> None:
        """ Refresh auth token before timeout"""
        url = '/aaaRefresh.json'
        if not self.is_authenticated:
            self.login()
        else:
            r = self.get(url)
            if r.ok:
                self.token = r.json()['imdata'][0]['aaaLogin']['attributes']['token']
            elif r.status_code == 403:
                logger.error(f'Not Authorized. HTTP Status Code: {r.status_code}')
                self.is_authenticated = False
            else:
                logger.error(f'Could not refresh token. HTTP Status Code: {r.status_code}')

    def logout(self) -> None:
        """ Logout and end the Session"""
        logger.info(f'logging out {self.ip}')
        logout_url = '/aaaLogout.json'
        self.login_thread.exit()
        self.post(logout_url)
