from utils.nxosrest import NexusREST
from utils.logger import logger
import os
import requests
import yaml
import pathlib
import sys
import argparse
from ansible.vars.manager import VariableManager
from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager
from pprint import pprint


class AHNexus(NexusREST):
    def __init__(self, ip, user, pwd):
        super().__init__(ip, user, pwd)
        self.ansible_config = {}
        self.all_vrfs_info = []
        self._bd = {}
        self._svi = {}
        self._vrf = {}

    @staticmethod
    def list_diff(list1: list, list2: list) -> list:
        s = set(list2)
        return [x for x in list1 if x not in s]

    @property
    def bd(self):
        if not self._bd:
            self._bd = super().get_bd()
        return list(self._bd.keys())

    def bd_exist(self, bd_id: str) -> bool:
        if bd_id in self.bd:
            return True
        return False

    def get_bd_name(self, bd_id: str):
        if bd_id in self.bd:
            return self._bd[bd_id]['name']
        return None

    def get_bd_encap(self, bd_id: str):
        if bd_id in self.bd:
            return self._bd[bd_id]['encap']
        return None

    @property
    def ans_bd(self):
        if not self.ansible_config:
            return None
        l2_vlans = self.ansible_config['l2_vlans']
        l3_vlans = self.ansible_config['l3_vlans']
        vrf = self.ansible_config['vrf']
        bd_list = list(l2_vlans.keys()) + list(l3_vlans.keys()) + list(vrf.keys())
        return list(bd_list)

    def get_ans_bd_name(self, bd_id: str):
        if not self.ansible_config:
            return None
        if bd_id in self.ansible_config['l2_vlans']:
            return self.ansible_config['l2_vlans'][bd_id]['name']
        if bd_id in self.ansible_config['l3_vlans']:
            return self.ansible_config['l3_vlans'][bd_id]['name']
        if bd_id in self.ansible_config['vrf']:
            name = self.ansible_config['vrf'][bd_id]['name']
            return f'VRF_{name}_L3VNI'
        return None

    @property
    def update_bd(self):
        update_validation_list = self.list_diff(self.bd, self.rem_bd)
        update_list = []
        for bd in update_validation_list:
            if self.get_bd_name(bd) != self.get_ans_bd_name(bd):
                update_list.append(bd)
        return update_list

    @property
    def new_bd(self):
        return self.list_diff(self.ans_bd, self.bd)

    @property
    def rem_bd(self):
        return self.list_diff(self.bd, self.ans_bd)

    @property
    def svi(self):
        if not self._svi:
            self._svi = super().get_svi()
        return list(self._svi.keys())

    def get_svi_name(self, svi_id: str):
        if svi_id in self.svi:
            return self._svi[svi_id]['descr']
        return None

    @property
    def ans_svi(self):
        if not self.ansible_config:
            return None
        l3_vlans = self.ansible_config['l3_vlans']
        vrf = self.ansible_config['vrf']
        svi_list = list(l3_vlans.keys()) + list(vrf.keys())
        return list(svi_list)

    def get_ans_svi_name(self, svi_id: str):
        if not self.ansible_config:
            return None
        if svi_id in self.ansible_config['l3_vlans']:
            vrf = self.ansible_config['l3_vlans'][svi_id]['vrf']
            name = self.ansible_config['l3_vlans'][svi_id]['name']
            return f'{vrf}_{name}'
        if svi_id in self.ansible_config['vrf']:
            name = self.ansible_config['vrf'][svi_id]['name']
            return f'VRF_{name}'
        return None

    @property
    def new_svi(self):
        return self.list_diff(self.ans_svi, self.svi)

    @property
    def rem_svi(self):
        return self.list_diff(self.svi, self.ans_svi)

    @property
    def update_svi(self):
        # check if VRF member, check ipv4, check ipv6, check descr
        update_validation_list = self.list_diff(self.svi, self.rem_svi)
        update_list = []
        for svi in update_validation_list:
            if self.get_svi_name(svi) != self.get_ans_svi_name(svi):
                update_list.append(svi)
        return update_list



SWITCH_HTTPS_PORT = '9443'


def ansible_yalm_config_parser(config: dict, hosts: list):
    """

    :param config: vrf and vlans AH config from ansible repo
    :param hosts: list of ansible_host for fabric leaf nodes
    :return: parsed dict with vrf, l2vlan, l3svi for each leaf
    """
    switch_info = dict()

    for leaf_name in hosts:
        switch_info[leaf_name] = {'l2_vlans': {}, 'l3_vlans': {}, 'vrf': {}}

    deploy_to_all = {'l2_vlans': {}, 'l3_vlans': {}, 'vrf': {}}

    # parse ansible var file for layer2 VLAN
    for vlan in config['l2_vlans']:
        l2_vlan = {str(vlan['vlan_id']): {'name': vlan['name'],
                                          'mcast_grp': vlan['mcast_grp']
                                          }}
        for host in vlan['deploy_to']:
            if host == 'all':
                deploy_to_all['l2_vlans'].update(l2_vlan)
            else:
                switch_info[host]['l2_vlans'].update(l2_vlan)

    # parse ansible var file for layer3 SVI
    for svi in config['l3_vlans']:
        if 'dhcp_relay' in svi:
            dhcp_relay = svi['dhcp_relay']
        else:
            dhcp_relay = 'false'
        l3_vlan = {str(svi['vlan_id']): {'name': svi['name'],
                                         'mcast_grp': svi['mcast_grp'],
                                         'vrf': svi['vrf'],
                                         'mtu': svi['mtu'],
                                         'ipv4': svi['ipv4'],
                                         'dhcp_relay': dhcp_relay
                                         }}
        for host in svi['deploy_to']:
            if host == 'all':
                deploy_to_all['l3_vlans'].update(l3_vlan)
            else:
                switch_info[host]['l3_vlans'].update(l3_vlan)

    # parse ansible var file for VRF
    for vrf in config['vrf']:
        vrf_info = {str(vrf['vlan_id']): {'description': vrf['description'],
                                          'name': vrf['name'],
                                          'ipv4': vrf['ipv4'],
                                          'ipv6': vrf['ipv6'],
                                          'has_exit': vrf['has_exit']
                                          }}
        for host in vrf['deploy_to']:
            if host == 'all':
                deploy_to_all['vrf'].update(vrf_info)
            else:
                switch_info[host]['vrf'].update(vrf_info)

    update_objects = ['l2_vlans', 'l3_vlans', 'vrf']

    for obj in update_objects:
        if deploy_to_all[obj]:
            for switch in switch_info.keys():
                switch_info[switch][obj].update(deploy_to_all[obj])
    return switch_info


def list_diff(list1: list, list2: list) -> list:
    s = set(list2)
    return [x for x in list1 if x not in s]


if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings()

    try:
        IP = os.environ['SWITCH_IP']
        username = os.environ['SWITCH_USER']
        password = os.environ['SWITCH_PASSWORD']
    except KeyError:
        logger.error('Switch ENV Variables Not Found. Exiting...')
        exit(1)

    file_vlans = pathlib.Path('main.yml')

    if not file_vlans.exists():
        print('File Not Found! Please check path and file name.')
        exit(1)
    else:
        # config = yaml.load(open(file_vlans), Loader=yaml.FullLoader)
        config_fabric = yaml.safe_load(open(file_vlans))

    file_hosts = 'hosts'
    # variable_manager = VariableManager()
    loader = DataLoader()
    inventory = InventoryManager(loader=loader, sources=file_hosts)
    variable_manager = VariableManager(loader=loader, inventory=inventory)
    hosts = variable_manager.get_vars()['groups']['leaf']

    parsed_ansible_config = ansible_yalm_config_parser(config_fabric, hosts)
    switches = dict()  # {'ansible_name': switch_object}

    for leaf in hosts:
        leaf_ansible = inventory.get_host(leaf)
        leaf_name = str(leaf_ansible)
        switch_ip = variable_manager.get_vars(host=leaf_ansible)['ansible_host']

        switches[leaf_name] = AHNexus(switch_ip + ':' + SWITCH_HTTPS_PORT, username, password)
        switches[leaf_name].ansible_config = parsed_ansible_config[leaf_name]
        switches[leaf_name].login()


        print(leaf_name)
        if switches[leaf].new_bd:
            print(' New VLAN:', switches[leaf].new_bd)
        if switches[leaf].rem_bd:
            print(' Delete VLAN:', switches[leaf].rem_bd)
        if switches[leaf].update_bd:
            print(' Update VLAN:', switches[leaf].update_bd)
        if switches[leaf].new_svi:
            print(' New SVI', switches[leaf].new_svi)
        if switches[leaf].rem_svi:
            print(' Delete SVI', switches[leaf].rem_svi)
        if switches[leaf].update_svi:
            print(' Update SVI', switches[leaf].update_svi)
