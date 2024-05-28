from utils.nxosrest import NexusREST
from utils.logger import logger
import os
import requests
import yaml
import pathlib
from ansible.vars.manager import VariableManager
from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager
import ipaddress as ip
from queue import Queue
from threading import Thread
import json


class AHNexus(NexusREST):
    def __init__(self, ip_addr, user, pwd):
        super().__init__(ip_addr, user, pwd)
        self.ansible_config = {}
        self._all_vrfs_v4info = []
        self._all_vrfs_v6info = []
        self._bd = {}
        self._svi = {}
        self._vrf = {}
        self._nh = {}
        self._v4static = {}  # ansible static property
        self._v6static = {}  # ansible static property
        self._v4static_resolved = {}
        self._v4static_unresolved = {}
        self._v4static_configured = {}
        self._v6static_resolved = {}
        self._v6static_unresolved = {}
        self._v6static_configured = {}
        self.name = ''
        self.warning_only = True

    @staticmethod
    def list_diff(list1: list, list2: list) -> list:
        """
        get list difference:
        :param list1:
        :param list2:
        :return: list1 - list2
        """
        s = set(list2)
        return [x for x in list1 if x not in s]

    @staticmethod
    def is_next_hop_found(nh1: dict, nh2_list: dict) -> bool:
        for nh2 in nh2_list:
            if nh1['nhAddr'] == nh2['nhAddr'] and nh1['nhIf'] == nh2['nhIf'] and nh1['nhVrf'] == nh2['nhVrf'] and nh1[
               'tag'] == nh2['tag']:
                return True
        return False

    def is_ans_v4nh_resolved(self, vrf_resolve: str, nh_resolve: str) -> bool:
        if not self.ansible_config:
            raise Exception('No Ansible Config for Switch')
        try:
            ipv4addr = ip.IPv4Address(nh_resolve)
        except ValueError as e:
            logger.error(f'Incorrect IP address for NextHop Resolving: {e}')
            exit(1)
        l3_vlans = self.ansible_config['l3_vlans']
        subnets = []
        for svi in l3_vlans:
            if l3_vlans[svi]['vrf'] == vrf_resolve:
                if 'ipv4' in l3_vlans[svi]:
                    for subnet in l3_vlans[svi]['ipv4']:
                        network = ip.IPv4Network(subnet['address'], strict=False)
                        subnets.append(network)
        for subnet in subnets:
            if ipv4addr in subnet:
                return True
        return False

    def is_ans_v6nh_resolved(self, vrf_resolve: str, nh6_resolve: str) -> bool:
        if not self.ansible_config:
            raise Exception('No Ansible Config for Switch')
        try:
            ipv6addr = ip.IPv6Address(nh6_resolve)
        except ValueError as e:
            logger.error(f'Incorrect IP address for NextHop Resolving: {e}')
            exit(1)
        if ipv6addr.is_link_local:
            return False
        l3_vlans = self.ansible_config['l3_vlans']
        subnets = []
        for svi in l3_vlans:
            if l3_vlans[svi]['vrf'] == vrf_resolve:
                if 'ipv6' in l3_vlans[svi]:
                    for subnet in l3_vlans[svi]['ipv6']:
                        network = ip.IPv6Network(subnet['address'], strict=False)
                        subnets.append(network)
        for subnet in subnets:
            if ipv6addr in subnet:
                return True
        return False

    def add_ansible_static(self, static_yml: dict):
        tag = static_yml['tag']
        for vrf_id in self.ans_vrf:
            if vrf_id in static_yml:
                # v4 static routes resolve
                if 'static_v4' in static_yml[vrf_id]:
                    if vrf_id not in self._v4static:
                        self._v4static[vrf_id] = {}
                    for v4route in static_yml[vrf_id]['static_v4']:
                        nh_dict = {}
                        nh_ip = v4route['nh']
                        nhif = v4route['nhIf'] if 'nhIf' in v4route else 'unspecified'
                        nh_dict['nhAddr'] = nh_ip
                        nh_dict['nhIf'] = nhif
                        dst = v4route['dst']
                        if 'name' in v4route:
                            name = v4route['name']
                            nh_dict['rtname'] = name
                        nh_dict['nhVrf'] = vrf_id
                        nh_dict['tag'] = tag
                        if self.is_ans_v4nh_resolved(vrf_id, nh_ip):
                            if dst not in self._v4static[vrf_id]:
                                self._v4static[vrf_id][dst] = []
                            self._v4static[vrf_id][dst].append(nh_dict)
                    # v6 static routes resolve
                    if 'static_v6' in static_yml[vrf_id]:
                        if vrf_id not in self._v6static:
                            self._v6static[vrf_id] = {}
                    for v6route in static_yml[vrf_id]['static_v6']:
                        nh_dict = {}
                        nh_ip6 = v6route['nh']
                        dst6 = v6route['dst']
                        nhif6 = v6route['nhIf'] if 'nhIf' in v6route else 'unspecified'
                        nh_dict['nhAddr'] = nh_ip6
                        nh_dict['nhIf'] = nhif6
                        if 'name' in v6route:
                            name6 = v6route['name']
                            nh_dict['rtname'] = name6
                        nh_dict['nhVrf'] = vrf_id
                        nh_dict['tag'] = tag
                        if (self.is_ans_v6nh_resolved(vrf_id, nh_ip6) or
                                (nhif6 != 'unspecified' and self.ans_svi_exist(nhif6[4:]))):
                            if dst6 not in self._v6static[vrf_id]:
                                self._v6static[vrf_id][dst6] = []
                            self._v6static[vrf_id][dst6].append(nh_dict)

    @property
    def v4static_ans(self):
        if self._v4static:
            return self._v4static

    @property
    def v6static_ans(self):
        if self._v6static:
            return self._v6static

    def is_sw_ip4nh_resolved(self, vrf_resolve: str, nh_resolve: str) -> bool:
        if not self._all_vrfs_v4info:
            self._all_vrfs_v4info = super().get_all_vrfs_info('ipv4')
        try:
            ipv4addr = ip.IPv4Address(nh_resolve)
        except ValueError as e:
            logger.error(f'Incorrect IP address for NextHop Resolving: {e}')
            exit(1)
        subnets = []
        for ipv4Dom in self._all_vrfs_v4info:
            vrf_id = ipv4Dom['ipv4Dom']['attributes']['name']
            if vrf_id not in ['management', 'default'] and vrf_id == vrf_resolve:
                children = ipv4Dom['ipv4Dom']['children'] if 'children' in ipv4Dom['ipv4Dom'] else []
                for child in children:
                    if 'ipv4If' in child:
                        if 'children' in child['ipv4If']:
                            if_children = child['ipv4If']['children']
                            for if_child in if_children:
                                if 'ipv4Addr' in if_child:
                                    ip_addr = if_child['ipv4Addr']['attributes']['addr']
                                    subnets.append(ip.IPv4Network(ip_addr, strict=False))
        for subnet in subnets:
            if ipv4addr in subnet:
                return True
        return False

    def is_sw_ip6nh_resolved(self, vrf_resolve: str, nh_resolve: str) -> bool:
        if not self._all_vrfs_v6info:
            self._all_vrfs_v6info = super().get_all_vrfs_info('ipv6')
        try:
            ipv6addr = ip.IPv6Address(nh_resolve)
        except ValueError as e:
            logger.error(f'Incorrect IPv6 address for NextHop Resolving: {e}')
            exit(1)
        if ipv6addr.is_link_local:
            return False
        subnets = []
        for ipv6Dom in self._all_vrfs_v6info:
            vrf_id = ipv6Dom['ipv6Dom']['attributes']['name']
            if vrf_id not in ['management', 'default'] and vrf_id == vrf_resolve:
                children = ipv6Dom['ipv6Dom']['children'] if 'children' in ipv6Dom['ipv6Dom'] else []
                for child in children:
                    if 'ipv6If' in child:
                        if 'children' in child['ipv6If']:
                            if_children = child['ipv6If']['children']
                            for if_child in if_children:
                                if 'ipv6Addr' in if_child:
                                    ip_addr = if_child['ipv6Addr']['attributes']['addr']
                                    subnets.append(ip.IPv6Network(ip_addr, strict=False))
        for subnet in subnets:
            if ipv6addr in subnet:
                return True
        return False

    def v4static_sw_parser(self):
        if not self._all_vrfs_v4info:
            self._all_vrfs_v4info = super().get_all_vrfs_info('ipv4')
        self._v4static_configured = {}
        self._v4static_resolved = {}
        self._v4static_unresolved = {}
        for ipv4Dom in self._all_vrfs_v4info:
            vrf_id = ipv4Dom['ipv4Dom']['attributes']['name']
            if vrf_id not in ['management', 'default']:
                if vrf_id not in self._v4static_configured:
                    self._v4static_configured[vrf_id] = {}
                children = ipv4Dom['ipv4Dom']['children'] if 'children' in ipv4Dom['ipv4Dom'] else []
                for child in children:
                    if 'ipv4Route' in child:
                        dst4 = child['ipv4Route']['attributes']['prefix']
                        self._v4static_configured[vrf_id][dst4] = []
                        nh4children = child['ipv4Route']['children']
                        for nh4child in nh4children:
                            nh4_ip = nh4child['ipv4Nexthop']['attributes']['nhAddr'][:-3]
                            nh4_ifc = nh4child['ipv4Nexthop']['attributes']['nhIf']
                            nh4_name = nh4child['ipv4Nexthop']['attributes']['rtname']
                            nh4_vrf = nh4child['ipv4Nexthop']['attributes']['nhVrf']
                            nh4_tag = nh4child['ipv4Nexthop']['attributes']['tag']
                            nh_dict = {'nhAddr': nh4_ip, 'nhIf': nh4_ifc, 'rtname': nh4_name, 'nhVrf': nh4_vrf,
                                       'tag': nh4_tag}
                            if self.is_sw_ip4nh_resolved(nh4_vrf, nh4_ip):
                                if vrf_id not in self._v4static_resolved:
                                    self._v4static_resolved[vrf_id] = {}
                                if dst4 not in self._v4static_resolved[vrf_id]:
                                    self._v4static_resolved[vrf_id][dst4] = []
                                self._v4static_resolved[vrf_id][dst4].append(nh_dict)
                            else:
                                if vrf_id not in self._v4static_unresolved:
                                    self._v4static_unresolved[vrf_id] = {}
                                if dst4 not in self._v4static_unresolved[vrf_id]:
                                    self._v4static_unresolved[vrf_id][dst4] = []
                                self._v4static_unresolved[vrf_id][dst4].append(nh_dict)
                            self._v4static_configured[vrf_id][dst4].append(nh_dict)
        # print(self.name, self._v4static_configured)
        # print(self.name, self._v4static_resolved)
        # print(self.name, self._v4static_unresolved)

    @property
    def v4static_sw_resolved(self):
        if not self._v4static_resolved:
            self.v4static_sw_parser()
        return self._v4static_resolved

    @property
    def v4static_sw_unresolved(self):
        if not self._v4static_unresolved:
            self.v4static_sw_parser()
        return self._v4static_unresolved

    @property
    def v4static_switch(self):
        if not self._v4static_configured:
            self.v4static_sw_parser()
        return self._v4static_configured

    def v4add_delete_static(self, static_dict: dict, status: str):
        if status not in ['deleted', 'created']:
            raise ValueError('status for static object should be deleted or created')
        inst_template = {"ipv4Inst": {"children": []}}
        url = '/mo/sys/ipv4/inst.json'
        for vrf in static_dict:
            vrf_template = {"ipv4Dom": {"attributes": {"name": ""}, "children": []}}
            vrf_template['ipv4Dom']['attributes']['name'] = vrf
            vrf_children = []

            for prefix in static_dict[vrf]:
                children = []
                template_ipv4route = {'ipv4Route': {'attributes': {'prefix': ''}, 'children': []}}
                nh_list = static_dict[vrf][prefix]
                for nh in nh_list:
                    template_nh = {"ipv4Nexthop": {"attributes": {}}}
                    nh_addr = nh['nhAddr']
                    nh['nhAddr'] = nh_addr + '/32'
                    nh['nhVrf'] = vrf
                    nh['status'] = status
                    template_nh['ipv4Nexthop']['attributes'] = nh
                    children.append(template_nh)
                template_ipv4route['ipv4Route']['attributes']['prefix'] = prefix
                template_ipv4route['ipv4Route']['children'] = children
                vrf_children.append(template_ipv4route)
                if vrf_children:
                    vrf_template['ipv4Dom']['children'] = vrf_children
            if vrf_template['ipv4Dom']['children']:
                inst_template['ipv4Inst']['children'].append(vrf_template)

        if inst_template['ipv4Inst']['children']:
            post_data = json.dumps(inst_template)
            if not self.warning_only:
                r = self.post(url, post_data)
                if r.ok:
                    logger.info(f'{self.ip}: HTTPS POST OK. Data: {post_data}')
            else:
                logger.info(f'Warning Only Mode: {self.name}: HTTPS POST OK. Data: {post_data}')

    def v4delete_static(self, static_dict: dict):
        return self.v4add_delete_static(static_dict, 'deleted')

    def v4add_static(self, static_dict: dict):
        return self.v4add_delete_static(static_dict, 'created')

    def v4delete_unresolved(self):
        if not self._v4static_unresolved:
            self.v4static_sw_parser()
        self.v4delete_static(self._v4static_unresolved)

    @property
    def new_v4static(self) -> dict:
        add = {}
        if not self.v4static_ans:
            return {}
        for vrf_id in self.v4static_ans:
            for dst in self.v4static_ans[vrf_id]:
                # next 5 lines - kostil ;)
                if vrf_id not in self.v4static_sw_resolved:
                    if vrf_id and vrf_id not in add:
                        add[vrf_id] = {}
                    add[vrf_id][dst] = self.v4static_ans[vrf_id][dst]
                    continue
                if dst not in self.v4static_sw_resolved[vrf_id]:
                    if vrf_id and vrf_id not in add:
                        add[vrf_id] = {}
                    add[vrf_id][dst] = self.v4static_ans[vrf_id][dst]
                elif dst in self.v4static_sw_resolved[vrf_id]:
                    for next_hop_ans in self.v4static_ans[vrf_id][dst]:
                        if not self.is_next_hop_found(next_hop_ans, self.v4static_sw_resolved[vrf_id][dst]):
                            if vrf_id and vrf_id not in add:
                                add[vrf_id] = {}
                            if dst not in add[vrf_id]:
                                add[vrf_id][dst] = []
                            add[vrf_id][dst].append(next_hop_ans)
        return add if add else {}

    @property
    def rem_v4static(self):
        remove = {}
        if not self.v4static_sw_resolved:
            return {}
        for vrf_id in self.v4static_sw_resolved:
            for dst in self.v4static_sw_resolved[vrf_id]:
                if dst not in self.v4static_ans[vrf_id]:
                    if vrf_id and vrf_id not in remove:
                        remove[vrf_id] = {}
                    remove[vrf_id][dst] = self.v4static_sw_resolved[vrf_id][dst]
                elif dst in self.v4static_ans[vrf_id]:
                    for next_hop_sw in self.v4static_sw_resolved[vrf_id][dst]:
                        if not self.is_next_hop_found(next_hop_sw, self.v4static_ans[vrf_id][dst]):
                            if vrf_id and vrf_id not in remove:
                                remove[vrf_id] = {}
                            if dst not in remove[vrf_id]:
                                remove[vrf_id][dst] = []
                            remove[vrf_id][dst].append(next_hop_sw)
        return remove if remove else {}

    def v6static_sw_parser(self):
        if not self._all_vrfs_v6info:
            self._all_vrfs_v6info = super().get_all_vrfs_info('ipv6')
        self._v6static_configured = {}
        self._v6static_resolved = {}
        self._v6static_unresolved = {}
        for ipv6Dom in self._all_vrfs_v6info:
            vrf_id = ipv6Dom['ipv6Dom']['attributes']['name']
            if vrf_id not in ['management', 'default']:
                if vrf_id not in self._v6static_configured:
                    self._v6static_configured[vrf_id] = {}
                children = ipv6Dom['ipv6Dom']['children'] if 'children' in ipv6Dom['ipv6Dom'] else []
                for child in children:
                    if 'ipv6Route' in child:
                        dst6 = child['ipv6Route']['attributes']['prefix']
                        self._v6static_configured[vrf_id][dst6] = []
                        nh4children = child['ipv6Route']['children']
                        for nh6child in nh4children:
                            nh_dict = {}
                            nh6_ip = nh6child['ipv6Nexthop']['attributes']['nhAddr'][:-4]
                            nh_dict['nhAddr'] = nh6_ip
                            nh6_ifc = nh6child['ipv6Nexthop']['attributes']['nhIf']
                            nh_dict['nhIf'] = nh6_ifc
                            if 'rtname' in nh6child['ipv6Nexthop']['attributes']:
                                nh6_name = nh6child['ipv6Nexthop']['attributes']['rtname']
                                nh_dict['rtname'] = nh6_name
                            nh6_vrf = nh6child['ipv6Nexthop']['attributes']['nhVrf']
                            nh_dict['nhVrf'] = nh6_vrf
                            nh6_tag = nh6child['ipv6Nexthop']['attributes']['tag']
                            nh_dict['tag'] = nh6_tag
                            if self.is_sw_ip6nh_resolved(nh6_vrf, nh6_ip) or (
                                    nh6_ifc != 'unspecified' and self.svi_exist(nh6_ifc[4:])):
                                if vrf_id not in self._v6static_resolved:
                                    self._v6static_resolved[vrf_id] = {}
                                if dst6 not in self._v6static_resolved[vrf_id]:
                                    self._v6static_resolved[vrf_id][dst6] = []
                                self._v6static_resolved[vrf_id][dst6].append(nh_dict)
                            else:
                                if vrf_id not in self._v6static_unresolved:
                                    self._v6static_unresolved[vrf_id] = {}
                                if dst6 not in self._v6static_unresolved[vrf_id]:
                                    self._v6static_unresolved[vrf_id][dst6] = []
                                self._v6static_unresolved[vrf_id][dst6].append(nh_dict)
                            self._v6static_configured[vrf_id][dst6].append(nh_dict)

    @property
    def v6static_sw_resolved(self):
        if not self._v6static_resolved:
            self.v6static_sw_parser()
        return self._v6static_resolved

    @property
    def v6static_sw_unresolved(self):
        if not self._v6static_unresolved:
            self.v6static_sw_parser()
        return self._v6static_unresolved

    @property
    def v6static_switch(self):
        if not self._v6static_configured:
            self.v6static_sw_parser()
        return self._v6static_configured

    def v6add_delete_static(self, static_dict: dict, status: str):
        if status not in ['deleted', 'created']:
            raise ValueError('status for static object should be deleted or created')
        inst_template = {"ipv6Inst": {"children": []}}
        url = '/mo/sys/ipv6/inst.json'
        for vrf in static_dict:
            vrf_template = {"ipv6Dom": {"attributes": {"name": ""}, "children": []}}
            vrf_template['ipv6Dom']['attributes']['name'] = vrf
            vrf_children = []

            for prefix in static_dict[vrf]:
                children = []
                template_ipv4route = {'ipv6Route': {'attributes': {'prefix': ''}, 'children': []}}
                nh_list = static_dict[vrf][prefix]
                for nh in nh_list:
                    template_nh = {"ipv6Nexthop": {"attributes": {}}}
                    nh_addr = nh['nhAddr']
                    nh['nhAddr'] = nh_addr + '/128'
                    nh['nhVrf'] = vrf
                    nh['status'] = status
                    template_nh['ipv6Nexthop']['attributes'] = nh
                    children.append(template_nh)
                template_ipv4route['ipv6Route']['attributes']['prefix'] = prefix
                template_ipv4route['ipv6Route']['children'] = children
                vrf_children.append(template_ipv4route)
                if vrf_children:
                    vrf_template['ipv6Dom']['children'] = vrf_children
            if vrf_template['ipv6Dom']['children']:
                inst_template['ipv6Inst']['children'].append(vrf_template)

        if inst_template['ipv6Inst']['children']:
            post_data = json.dumps(inst_template)
            if not self.warning_only:
                r = self.post(url, post_data)
                if r.ok:
                    logger.info(f'{self.ip}: HTTPS POST OK. Data: {post_data}')
            else:
                logger.info(f'Warning Only Mode: {self.name}: HTTPS POST OK. Data: {post_data}')

    def v6delete_static(self, static_dict: dict):
        return self.v6add_delete_static(static_dict, 'deleted')

    def v6add_static(self, static_dict: dict):
        return self.v6add_delete_static(static_dict, 'created')

    def v6delete_unresolved(self):
        if not self._v6static_unresolved:
            self.v6static_sw_parser()
        self.v6delete_static(self._v6static_unresolved)

    @property
    def new_v6static(self) -> dict:
        """
        defines v6 statics to be added.
        """
        add = {}
        if not self.v6static_ans:
            return {}
        for vrf_id in self.v6static_ans:
            for dst in self.v6static_ans[vrf_id]:
                if vrf_id in self.v6static_sw_resolved:
                    if dst not in self.v6static_sw_resolved[vrf_id]:
                        if vrf_id and vrf_id not in add:
                            add[vrf_id] = {}
                        add[vrf_id][dst] = self.v6static_ans[vrf_id][dst]
                    elif dst in self.v6static_sw_resolved[vrf_id]:
                        for next_hop_ans in self.v6static_ans[vrf_id][dst]:
                            if not self.is_next_hop_found(next_hop_ans, self.v6static_sw_resolved[vrf_id][dst]):
                                if vrf_id and vrf_id not in add:
                                    add[vrf_id] = {}
                                if dst not in add[vrf_id]:
                                    add[vrf_id][dst] = []
                                add[vrf_id][dst].append(next_hop_ans)
        return add if add else {}

    @property
    def rem_v6static(self):
        """
        defines v6 statics to be removed.
        """
        remove = {}
        if not self.v6static_sw_resolved:
            return {}
        for vrf_id in self.v6static_sw_resolved:
            for dst in self.v6static_sw_resolved[vrf_id]:
                if dst not in self.v6static_ans[vrf_id]:
                    if vrf_id and vrf_id not in remove:
                        remove[vrf_id] = {}
                    remove[vrf_id][dst] = self.v6static_sw_resolved[vrf_id][dst]
                elif dst in self.v6static_ans[vrf_id]:
                    for next_hop_sw in self.v6static_sw_resolved[vrf_id][dst]:
                        if not self.is_next_hop_found(next_hop_sw, self.v6static_ans[vrf_id][dst]):
                            if vrf_id and vrf_id not in remove:
                                remove[vrf_id] = {}
                            if dst not in remove[vrf_id]:
                                remove[vrf_id][dst] = []
                            remove[vrf_id][dst].append(next_hop_sw)
        return remove if remove else {}

    @property
    def vrf(self):
        """
        to get VRF names, encap, descr
        :return: list of vrfs
        """
        if not self._vrf:
            self._vrf = super().get_vrf()
        return list(self._vrf.keys())

    def vrf_exist(self, vrf_id: str) -> bool:
        """
        :param vrf_id: VRF Name. String.
        :return: boolean True if VRF exist on switch, False if not.
        """
        if vrf_id in self.vrf:
            return True
        return False

    def get_vrf_desc(self, vrf_id: str):
        """
        get VRF description
        :param vrf_id: VRF Name. String.
        :return: vrf name if VRF exists. None if not.
        """
        if vrf_id in self.vrf:
            return self._vrf[vrf_id]['descr']
        return None

    def get_vrf_encap(self, vrf_id: str):
        """
        get VRF VXLAN encap ID
        :param vrf_id: VRF name. String.
        :return: string VXLAN ID if vrf exists. None if not.
        """
        if vrf_id in self.vrf:
            return self._vrf[vrf_id]['encap']
        return None

    @property
    def ans_vrf(self):
        """
        :return: list of VRFs from ansible yaml config. VRFs supposed to be configured on switch
        """
        if not self.ansible_config:
            return None
        vrf = self.ansible_config['vrf']
        ans_vrf = []
        for item in vrf:
            ans_vrf.append(vrf[item]['name'])
        return ans_vrf

    def get_ans_vrf_desc(self, vrf_id: str):
        if not self.ansible_config:
            return None
        vrf = self.ansible_config['vrf']
        ans_vrf_desc = None
        for item in vrf:
            if vrf[item]['name'] == vrf_id:
                ans_vrf_desc = vrf[item]['description']
        return ans_vrf_desc

    def get_ans_vrf_bd(self, vrf_id: str):
        if not self.ansible_config:
            return None
        vrf = self.ansible_config['vrf']
        ans_vrf_bd = None
        for item in vrf:
            if vrf[item]['name'] == vrf_id:
                ans_vrf_bd = item
        return ans_vrf_bd

    @property
    def new_vrf(self):
        """
        function to get list of VRF to be added to the switch
        :return: list of VRF
        """
        return self.list_diff(self.ans_vrf, self.vrf)

    @property
    def rem_vrf(self):
        """
        function to get list of VRFs to be removed from the switch
        :return: list of VRFs
        """
        return self.list_diff(self.vrf, self.ans_vrf)

    @property
    def update_vrf(self):
        update_validation_list = self.list_diff(self.vrf, self.rem_vrf)
        update_list = []
        for vrf in update_validation_list:
            if self.get_vrf_desc(vrf) != self.get_ans_vrf_desc(vrf):
                update_list.append(vrf)
        return update_list

    @property
    def bd(self):
        """
        :return: list of BD ID
        """
        if not self._bd:
            self._bd = super().get_bd()
        return list(self._bd.keys())

    def bd_exist(self, bd_id: str) -> bool:
        """
        :param bd_id: Bridge Domain (VLAN) ID. String.
        :return: boolean True if BD exist on switch, False if not.
        """
        if bd_id in self.bd:
            return True
        return False

    def get_bd_name(self, bd_id: str):
        """
        get bridge domain (VLAN) name
        :param bd_id: Bridge Domain (VLAN) ID. String.
        :return: string name if bd exists. None if not.
        """
        if bd_id in self.bd:
            return self._bd[bd_id]['name']
        return None

    def get_bd_encap(self, bd_id: str):
        """
        get Bridge Domain VXLAN encap ID
        :param bd_id: Bridge Domain (VLAN) ID. String.
        :return: string VXLAN ID if bd exists. None if not.
        """
        if bd_id in self.bd:
            return self._bd[bd_id]['encap']
        return None

    @property
    def ans_bd(self):
        """

        :return: list of BD from ansible yaml config. BD supposed to be configured on switch
        """
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

    def get_ans_bd_mcast(self, bd_id: str):
        if not self.ansible_config:
            return None
        if bd_id in self.ansible_config['l2_vlans']:
            return self.ansible_config['l2_vlans'][bd_id]['mcast_grp']
        if bd_id in self.ansible_config['l3_vlans']:
            return self.ansible_config['l3_vlans'][bd_id]['mcast_grp']
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
        """
        function to get list of BD to be added to the switch
        :return: list of BD
        """
        return self.list_diff(self.ans_bd, self.bd)

    @property
    def rem_bd(self):
        """
        function to get list of BD to be removed from the switch
        :return: list of BD
        """
        return self.list_diff(self.bd, self.ans_bd)

    @property
    def svi(self):
        if not self._svi:
            self._svi = super().get_svi()
        return list(self._svi.keys())

    def svi_exist(self, svi_id: str):
        return True if svi_id in self.svi else False

    def get_svi_name(self, svi_id: str):
        if svi_id in self.svi:
            return self._svi[svi_id]['descr']
        return None

    def get_svi_vrf(self, svi_id: str):
        """
        function to get SVI VRF Name
        :param svi_id: string with SVI ID (VLAN ID)
        :return: string with SVI VRF Name
        """
        if svi_id in self.svi:
            return self._svi[svi_id]['vrf']

    @property
    def ans_svi(self):
        if not self.ansible_config:
            return None
        l3_vlans = self.ansible_config['l3_vlans']
        vrf = self.ansible_config['vrf']
        svi_list = list(l3_vlans.keys()) + list(vrf.keys())
        return list(svi_list)

    def ans_svi_exist(self, svi_id: str) -> bool:
        """
        :param svi_id: SVI (VLAN) ID. String.
        :return: boolean True if SVI exist in ansible config on SW, False if not.
        """
        if svi_id in self.ans_svi:
            return True
        return False

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
        """
        function to get list of SVI to be added to the switch
        :return: list of SVI
        """
        return self.list_diff(self.ans_svi, self.svi)

    @property
    def rem_svi(self):
        """
        function to get list of SVI to be removed from the switch
        :return: list of SVI
        """
        return self.list_diff(self.svi, self.ans_svi)

    @property
    def update_svi(self):
        # check if VRF member, check ipv4, check ipv6, check descr, dhcp relay
        update_validation_list = self.list_diff(self.svi, self.rem_svi)
        update_list = []
        for svi in update_validation_list:
            if self.get_svi_name(svi) != self.get_ans_svi_name(svi):
                update_list.append(svi)
        return update_list


SWITCH_HTTPS_PORT = '9443'


def ansible_yalm_config_parser(config: dict, host_list: list):
    """

    :param config: vrf and vlans AH config from ansible repo
    :param host_list: list of ansible_host for fabric leaf nodes
    :return: parsed dict with vrf, l2vlan, l3svi for each leaf
    """
    switch_info = dict()

    for node in host_list:
        switch_info[node] = {'l2_vlans': {}, 'l3_vlans': {}, 'vrf': {}}

    deploy_to_all = {'l2_vlans': {}, 'l3_vlans': {}, 'vrf': {}}

    # parse ansible var file for layer2 VLAN
    if 'l2_vlans' in config and config['l2_vlans']:
        for vlan in config['l2_vlans']:
            if 'mcast_grp' in vlan:
                mcast_grp = vlan['mcast_grp']
            else:
                mcast_grp = '0.0.0.0'
            l2_vlan = {str(vlan['vlan_id']): {'name': vlan['name'],
                                              'mcast_grp': mcast_grp
                                              }}
            for host in vlan['deploy_to']:
                if host == 'all':
                    deploy_to_all['l2_vlans'].update(l2_vlan)
                else:
                    switch_info[host]['l2_vlans'].update(l2_vlan)

    # parse ansible var file for layer3 SVI
    if 'l3_vlans' in config and config['l3_vlans']:
        for svi in config['l3_vlans']:
            if 'dhcp_relay' in svi:
                dhcp_relay = svi['dhcp_relay']
            else:
                dhcp_relay = 'false'
            ipv4 = svi['ipv4'] if 'ipv4' in svi else ''
            ipv6 = svi['ipv6'] if 'ipv6' in svi else ''
            l3_vlan = {str(svi['vlan_id']): {'name': svi['name'],
                                             'mcast_grp': svi['mcast_grp'],
                                             'vrf': svi['vrf'],
                                             'mtu': svi['mtu'],
                                             'ipv4': ipv4,
                                             'ipv6': ipv6,
                                             'dhcp_relay': dhcp_relay
                                             }}
            for host in svi['deploy_to']:
                if host == 'all':
                    deploy_to_all['l3_vlans'].update(l3_vlan)
                else:
                    switch_info[host]['l3_vlans'].update(l3_vlan)

    # parse ansible var file for VRF
    if 'vrf' in config and config['vrf']:
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


def get_actual_cfg_lazy_engineers():
    resolved = switches['ams-am7-0315-leaf-sw0'].v4static_sw_resolved
    yaml_list = []
    for route in resolved['GRT']:
        dst = route
        if dst not in switches['ams-am7-0315-leaf-sw0'].v4static_ans['GRT']:
            nh_list = resolved['GRT'][dst]
            for nh_item in nh_list:
                name = nh_item['rtname']
                next_hop = nh_item['nhAddr']
                route_dict = {'dst': dst, 'name': name, 'nh': next_hop}
                yaml_list.append(route_dict)
        elif dst in switches['ams-am7-0315-leaf-sw0'].v4static_ans['GRT']:
            if switches['ams-am7-0315-leaf-sw0'].v4static_ans['GRT'][dst] != resolved['GRT'][dst]:
                nh_list = resolved['GRT'][dst]
                for nh_item in nh_list:
                    name = nh_item['rtname']
                    next_hop = nh_item['nhAddr']
                    route_dict = {'dst': dst, 'name': name, 'nh': next_hop}
                    yaml_list.append(route_dict)
    print(yaml.dump(yaml_list, default_flow_style=None))


def thread_worker(queue):
    while True:
        node = queue.get()
        node.login()

        if node.new_bd:
            print(f'Node: {node.name:25} New VLAN:', node.new_bd)
            for bd in node.new_bd:
                bd_id = bd
                bd_name = node.get_ans_bd_name(bd)
                bd_ecap = ENCAP_PREFIX + bd
                bd_mcast_grp = node.get_ans_bd_mcast(bd)
                if not bd_mcast_grp:
                    bd_mcast_grp = '0.0.0.0'
                if not node.warning_only:
                    node.add_bd(bd_id, bd_ecap, bd_name)
                    node.add_l2vni_rd(bd_ecap)
                    node.add_vni_nve(bd_ecap, bd_mcast_grp)
                else:
                    logger.info(f'Node: {node.name:25} Warning Only Mode! Adding Layer2 '
                                f'{bd_id} {bd_name} with VNI: {bd_ecap}')
        if node.new_svi:
            print(f'Node: {node.name:25} New SVI:', node.new_svi)

        if node.rem_svi:
            print(f'Node: {node.name:25} Delete SVI:', node.rem_svi)
        if node.update_svi:
            print(f'Node: {node.name:25} Update SVI:', node.update_svi)

        if node.rem_bd:
            print(f'Node: {node.name:25} Delete VLAN:', node.rem_bd)

            for bd in node.rem_bd:
                bd_id = bd
                bd_ecap = ENCAP_PREFIX + bd
                if not node.warning_only:
                    node.delete_vni_nve(bd_ecap)
                    node.delete_l2vni_rd(bd_ecap)
                    node.delete_bd(bd_id)
                else:
                    logger.info(f'Node: {node.name:25} Warning Only Mode! Deleting Layer2 '
                                f'{bd_id} with VNI: {bd_ecap}')

        if node.update_bd:
            print(f'Node: {node.name:25} Update VLAN:', node.update_bd)

        if node.new_vrf:
            print(f'Node: {node.name:25} New VRF:', node.new_vrf)
        if node.rem_vrf:
            print(f'Node: {node.name:25} Delete VRF:', node.rem_vrf)
        if node.update_vrf:
            print(f'Node: {node.name:25} Update VRF:', node.update_vrf)

        # print(f'{node.name} v4resolved: {node.v4static_sw_resolved}')
        # print(f'{node.name} v6resolved: {node.v6static_sw_resolved}')

        # node.v4delete_unresolved()
        # node.v6delete_unresolved()

        if node.new_v4static:
            node.v4add_static(node.new_v4static)
        if node.rem_v4static:
            node.v4delete_static(node.rem_v4static)

        if node.new_v6static:
            node.v6add_static(node.new_v6static)

        if node.rem_v6static:
            node.v6delete_static(node.rem_v6static)

        queue.task_done()


if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings()

    try:
        username = os.environ['SSH_USER_ID']
        password = os.environ['SSH_PASSWORD']
    except KeyError:
        logger.error('Switch ENV Variables Not Found. Exiting...')
        exit(1)

    file_vlans = pathlib.Path('vrf_vlans/main.yml')
    file_static = pathlib.Path('static_routes/main.yml')

    if not file_vlans.exists() or not file_static.exists():
        print('File Not Found! Please check path and file name.')
        exit(1)
    else:
        config_fabric = yaml.safe_load(open(file_vlans))
        static_routes = yaml.safe_load(open(file_static))

    file_hosts = 'hosts'

    ENCAP_PREFIX = '500'

    loader = DataLoader()
    inventory = InventoryManager(loader=loader, sources=file_hosts)
    variable_manager = VariableManager(loader=loader, inventory=inventory)
    hosts = variable_manager.get_vars()['groups']['leaf']
    switches = dict()  # {'ansible_name': switch_object}

    parsed_ansible_config = ansible_yalm_config_parser(config_fabric, hosts)

    threading_queue = Queue(maxsize=0)
    num_threads = 10

    for i in range(num_threads):
        worker = Thread(target=thread_worker, args=(threading_queue,))
        worker.setDaemon(True)
        worker.start()

    for leaf in hosts:
        leaf_ansible = inventory.get_host(leaf)
        leaf_name = str(leaf_ansible)
        switch_ip = variable_manager.get_vars(host=leaf_ansible)['ansible_host']

        switches[leaf_name] = AHNexus(switch_ip + ':' + SWITCH_HTTPS_PORT, username, password)
        switches[leaf_name].ansible_config = parsed_ansible_config[leaf_name]
        switches[leaf_name].add_ansible_static(static_routes)
        switches[leaf_name].name = leaf_name

        threading_queue.put(switches[leaf_name])

    threading_queue.join()

    # add test BD
    # switches['ams-am7-0332-leaf-sw0'].add_bd('666','500666', 'Evil_VLAN')
    # switches['ams-am7-0332-leaf-sw0'].add_l2vni_rd('500666')
    # switches['ams-am7-0332-leaf-sw0'].add_vni_nve('500666', '239.0.130.7')

    # switches['ams-am7-0332-leaf-sw1'].add_bd('666','500666', 'Evil_VLAN')
    # switches['ams-am7-0332-leaf-sw1'].add_l2vni_rd('500666')
    # switches['ams-am7-0332-leaf-sw1'].add_vni_nve('500666','239.0.130.7')

    # delete test BD
    # switches['ams-am7-0332-leaf-sw0'].delete_vni_nve('500666')
    # switches['ams-am7-0332-leaf-sw0'].delete_l2vni_rd('500666')
    # switches['ams-am7-0332-leaf-sw0'].delete_bd('666')

    # switches['ams-am7-0332-leaf-sw1'].delete_vni_nve('500666')
    # switches['ams-am7-0332-leaf-sw1'].delete_l2vni_rd('500666')
    # switches['ams-am7-0332-leaf-sw1'].delete_bd('666')

    # add test VRF
#    switches['ams-am7-0332-leaf-sw0'].add_bd('666', '500661', 'Evil_VLAN')
#    switches['ams-am7-0332-leaf-sw0'].add_evpn_vrf('TEST1', 'my test vrf', '500661')
#    vrf_bd = ENCAP_PREFIX + switches['ams-am7-0332-leaf-sw0'].get_ans_vrf_bd('TEST1')
#    switches['ams-am7-0332-leaf-sw0'].associate_vrf_nve(vrf_bd)

    # delete test VRF
    # ToDo: add get_sw_vrf_bd
#    vrf_bd = ENCAP_PREFIX + switches['ams-am7-0332-leaf-sw0'].get_sw_vrf_bd('TEST1')
#    switches['ams-am7-0332-leaf-sw0'].disassociate_vrf_nve(vrf_bd)
#    switches['ams-am7-0332-leaf-sw0'].delete_evpn_vrf('TEST1')
#    switches['ams-am7-0332-leaf-sw0'].delete_bd('666')
