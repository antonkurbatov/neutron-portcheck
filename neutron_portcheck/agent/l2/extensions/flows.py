import collections
import re

import netaddr
from neutron.agent.linux.openvswitch_firewall import firewall as ovs_firewall
from neutron.common import constants
from neutron_lib import constants as lib_const
from oslo_log import log as logging


LOG = logging.getLogger(__name__)


class Flows(object):
    pattern = re.compile('table=(\d+).*priority=(\d+)')

    def __init__(self, raw_flows):
        self._flows_map = collections.defaultdict(
            lambda: collections.defaultdict(list))
        for flow in raw_flows:
            match = self.pattern.search(flow)
            if not match:
                LOG.warning('Skipping weird flow: %s', flow)
                continue
            table, priority = match.groups()
            self._flows_map[int(table)][int(priority)].append(flow)

    @staticmethod
    def _numeric_ct_state(ct_state):
        return ovs_firewall.OVSFirewallDriver._numeric_ct_state(ct_state)

    def _check_ct_state(self, flow, value):
        # ct_state items are not ordered, that is why needs to
        # compare numeric values rather then strings.
        value_num = self._numeric_ct_state(value)
        parts = re.split("[ ,]", flow)
        for part in parts:
            if 'ct_state' not in part:
                continue
            ct_state = part.split('=')[1]
            ct_state_num = self._numeric_ct_state(ct_state)
            if ct_state_num == value_num:
                return True
        return False

    def _match_key_value(self, key, value, flow):
        if key == 'ct_state':
            return self._check_ct_state(flow, value)
        if key == 'protocol':
            v1 = ',%s,' % value
            v2 = ',%s ' % value
            return v1 in flow or v2 in flow
        key_value = '%s=%s' % (key, value)
        return key_value in flow

    def filter_flows(self, table, priority, **kwargs):
        flows = []
        for flow in self._flows_map[table][priority]:
            for key, value in kwargs.items():
                if not self._match_key_value(key, value, flow):
                    break
            else:
                flows.append(flow)
        return flows

    @staticmethod
    def normalize_params(**kwargs):
        rv = {}
        keys_map = {
            'eth_src': 'dl_src',
            'eth_dst': 'dl_dst',
            'udp_src': 'tp_src',
            'udp_dst': 'tp_dst',
            'icmpv6_type': 'icmp_type',
            'reg_port': 'reg5',
            'reg_net': 'reg6',
            'ipv4_src': 'nw_src',
            'ipv4_dst': 'nw_dst',
            'vlan_vid': 'dl_vlan',
        }
        actions_map = {
            'normal': 'NORMAL',
            'pop_vlan': 'strip_vlan',
            'reg5': 'NXM_NX_REG5[]',
            'reg6': 'NXM_NX_REG6[]',
            'reg7': 'NXM_NX_REG7[]',
            'ct_mark': 'NXM_NX_CT_MARK[]',
        }
        protocol_map = {
            (constants.ETHERTYPE_IP, None): 'ip',
            (constants.ETHERTYPE_IPV6, None): 'ipv6',
            (constants.ETHERTYPE_IP, lib_const.PROTO_NUM_UDP): 'udp',
            (constants.ETHERTYPE_IPV6, lib_const.PROTO_NUM_UDP): 'udp6',
            (constants.ETHERTYPE_IPV6, lib_const.PROTO_NUM_IPV6_ICMP): 'icmp6',
            (constants.ETHERTYPE_ARP, None): 'arp',
        }

        for key, value in kwargs.items():
            key = keys_map.get(key, key)
            if key in ['reg5', 'reg6']:
                value = hex(value)
            if key in ['nw_src', 'nw_dst', 'ipv6_src', 'ipv6_dst']:
                ip_net = netaddr.IPNetwork(value)
                if ((ip_net.version == 4 and ip_net.prefixlen == 32) or
                        (ip_net.version == 6 and ip_net.prefixlen == 128)):
                    value = str(ip_net.ip)
            if key == 'dl_vlan':
                value = value ^ 0x1000
            if key == 'ct_mark' and value != 0:
                value = hex(value)
            if key == 'actions':
                for cur, new in actions_map.items():
                    value = value.replace(cur, new)
                while 'set_field' in value:
                    m = re.search('(.*)set_field:(\d+)(.*)', value)
                    if not m:
                        break
                    head, load, tail = m.groups()
                    value = '{}load:{}{}'.format(head, hex(int(load)), tail)
            if key == 'eth_type':
                eth_type = kwargs['eth_type']
                ip_proto = kwargs.get('ip_proto', None)
                protocol = protocol_map.get((eth_type, ip_proto))
                if protocol:
                    rv['protocol'] = protocol
                else:
                    LOG.warning('Skipping protocol checking for '
                                'eth_type=%s,ip_proto=%s', eth_type, ip_proto)
                continue
            if key == 'ip_proto':
                continue
            rv[key] = value
        return rv
