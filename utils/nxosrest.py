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
        """
        :return: {'220': {'name': 'SPT_Private_LAN220', 'encap': 'vxlan-500220'},
                  '2309': {'name': 'Proluna_PCI_DSS_WAN', 'encap': 'vxlan-5002309'}}
        """
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
            if 'accEncap' in bd['l2BD']['attributes']:
                bd_encap = bd['l2BD']['attributes']['accEncap']
            else:
                bd_encap = 'Unknown'
            bd_dict[bd_id] = {'name': bd_name, 'encap': bd_encap}
        return bd_dict

    def add_bd(self, bd_id: int, vxlan_id: int, name: str):
        url = f'/api/mo/sys/bd.json'
        bd = {
            "l2BD": {
                "attributes": {
                    "accEncap": f"vxlan-{vxlan_id}",
                    "dn": f"sys/bd/bd-[vlan-{str(bd_id)}]",
                    "fabEncap": f"vlan-{str(bd_id)}",
                    "id": str(bd_id),
                    "name": name,
                    "status": "created"
                }
            }
        }

    def delete_bd(self, bd_id: int):
        url = f'/api/mo/sys/bd.json'
        bd = {
            "l2BD": {
                "attributes": {
                    "dn": f"sys/bd/bd-[vlan-{bd_id}]",
                    "status": "deleted"
                }
            }
        }

# switch info /api/mo/sys.json
# switch full conf : /api/mo/sys.json?rsp-subtree=full&rsp-prop-include=set-config-only

    def get_svi(self):
        """

        :return: dict with all SVIs {'VLAN_ID':{'descr':'DESCRIPTION','vrf':'VRF_NAME'}}
        example: {'2500': {'descr': 'WAN_DIFF_2500', 'vrf': 'GRT'},
                  '2402': {'descr': 'MGMT_chat', 'vrf': 'GRT'}}
        """
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


    def add_svi(self, vlan_id: int, descr: str, vrf: str):
        url = f'/node/mo/sys/intf/svi-[vlan{str(vlan_id)}].json'
        svi_if = {"sviIf": {
            "attributes": {
                "adminSt": "up",
                "descr": descr,
                "dn": f"sys/intf/svi-[vlan{str(vlan_id)}]",
                "id": f"vlan{str(vlan_id)}",
                "vlanId": str(vlan_id)
            },
            "children": [
                {
                    "nwRtVrfMbr": {
                        "attributes": {
                            "rn": "rtvrfMbr",
                            "tDn": f"sys/inst-{vrf}"
                        }
                    }
                }
            ]
        }
        }

    def delete_svi(self, vlan_id: int):
        url = f'/node/mo/sys/intf/svi-[vlan{str(vlan_id)}].json'
        svi_if = {"sviIf": {
            "attributes": {
                "dn": f"sys/intf/svi-[vlan{str(vlan_id)}]",
                "id": f"vlan{str(vlan_id)}",
                "vlanId": str(vlan_id),
                "status": "deleted"
            }}}


    def get_all_vrfs_info(self):
        """
        :return: list with data for all vrfs: [{'ipv4Dom':
        {'attributes':{}, 'children'[{'ipv4Route':{},{'ipv4If':{}}]:}},{}]
        """
        url = '/mo/sys/ipv4/inst.json?rsp-subtree=full&rsp-prop-include=set-config-only'
        r = self.get(url)
        if r is None:
            return
        data = r.json()['imdata'][0]['ipv4Inst']['children']
        return data

    def get_vrf(self):
        """
        :return: dict of vrfs: key = name, {rd:'', encap:''}
        """
        url = '/node/class/l3Inst.json?rsp-subtree=full&rsp-prop-include=set-config-only'
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

    def add_vrf(self, vrf_name: str, descr: str, encap: int):
        vrf = {
            "topSystem": {
                "children": [{
                    "l3Inst": {
                        "attributes": {
                            "descr": f"{descr}",
                            "dn": f"sys/inst-{vrf_name}",
                            "encap": f"vxlan-{str(encap)}",
                            "name": f"{vrf_name}"
                        },
                        "children": [
                            {
                                "rtctrlDom": {
                                    "attributes": {
                                        "name": vrf_name,
                                        "rd": "rd:unknown:0:0",
                                        "rn": f"dom-{vrf_name}"
                                    },
                                    "children": [
                                        {
                                            "rtctrlDomAf": {
                                                "attributes": {
                                                    "rn": "af-[ipv6-ucast]",
                                                    "type": "ipv6-ucast"
                                                },
                                                "children": [
                                                    {
                                                        "rtctrlAfCtrl": {
                                                            "attributes": {
                                                                "rn": "ctrl-[l2vpn-evpn]",
                                                                "type": "l2vpn-evpn"
                                                            },
                                                            "children": [
                                                                {
                                                                    "rtctrlRttP": {
                                                                        "attributes": {
                                                                            "rn": "rttp-export",
                                                                            "type": "export"
                                                                        },
                                                                        "children": [
                                                                            {
                                                                                "rtctrlRttEntry": {
                                                                                    "attributes": {
                                                                                        "rn": "ent-[route-target:unknown:0:0]",
                                                                                        "rtt": "route-target:unknown:0:0"
                                                                                    }
                                                                                }
                                                                            }
                                                                        ]
                                                                    }
                                                                },
                                                                {
                                                                    "rtctrlRttP": {
                                                                        "attributes": {
                                                                            "rn": "rttp-import",
                                                                            "type": "import"
                                                                        },
                                                                        "children": [
                                                                            {
                                                                                "rtctrlRttEntry": {
                                                                                    "attributes": {
                                                                                        "rn": "ent-[route-target:unknown:0:0]",
                                                                                        "rtt": "route-target:unknown:0:0"
                                                                                    }
                                                                                }
                                                                            }
                                                                        ]
                                                                    }
                                                                }
                                                            ]
                                                        }
                                                    }
                                                ]
                                            }
                                        },
                                        {
                                            "rtctrlDomAf": {
                                                "attributes": {
                                                    "rn": "af-[ipv4-ucast]",
                                                    "type": "ipv4-ucast"
                                                },
                                                "children": [
                                                    {
                                                        "rtctrlAfCtrl": {
                                                            "attributes": {
                                                                "rn": "ctrl-[l2vpn-evpn]",
                                                                "type": "l2vpn-evpn"
                                                            },
                                                            "children": [
                                                                {
                                                                    "rtctrlRttP": {
                                                                        "attributes": {
                                                                            "rn": "rttp-export",
                                                                            "type": "export"
                                                                        },
                                                                        "children": [
                                                                            {
                                                                                "rtctrlRttEntry": {
                                                                                    "attributes": {
                                                                                        "rn": "ent-[route-target:unknown:0:0]",
                                                                                        "rtt": "route-target:unknown:0:0"
                                                                                    }
                                                                                }
                                                                            }
                                                                        ]
                                                                    }
                                                                },
                                                                {
                                                                    "rtctrlRttP": {
                                                                        "attributes": {
                                                                            "rn": "rttp-import",
                                                                            "type": "import"
                                                                        },
                                                                        "children": [
                                                                            {
                                                                                "rtctrlRttEntry": {
                                                                                    "attributes": {
                                                                                        "rn": "ent-[route-target:unknown:0:0]",
                                                                                        "rtt": "route-target:unknown:0:0"
                                                                                    }
                                                                                }
                                                                            }
                                                                        ]
                                                                    }
                                                                }
                                                            ]
                                                        }
                                                    }
                                                ]
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                }]}}

    def delete_vrf(self, vrf_name: str):
        vrf = {
            "topSystem": {
                "children": [
                    {
                        "l3Inst": {
                            "attributes": {
                                "name": f"{vrf_name}",
                                "status": "deleted"
                            }}}]}}

    def login(self) -> None:
        """ Login into the Switch. Get Token"""
        url = '/aaaLogin.json'
        auth_body = {"aaaUser": {"attributes": {"name": self.user, "pwd": self.pwd}}}
        post_data = json.dumps(auth_body)
        logger.debug(f'logging into {self.ip}')
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
        logger.debug(f'logging out {self.ip}')
        logout_url = '/aaaLogout.json'
        self.login_thread.exit()
        self.post(logout_url)


## /api/node/mo/sys/ipv4/inst/dom-GRT.json?rsp-subtree=full&rsp-prop-include=set-config-only
## static routes. Need to filter only static route object.


## VRF info including static routes and ipv4 addresses for SVI's
##         '/api/mo/sys/ipv4/inst/dom-GRT.json?rsp-subtree=full&rsp-prop-include=set-config-only'
##