# Copyright 2023 Acronis
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
import hashlib
import json

import netaddr
from neutron_lib.agent import l2_extension
from neutron_lib.agent import topics
from neutron_lib.callbacks import events as callbacks_events
from neutron_lib.callbacks import registry as callbacks_registry
from neutron_lib.callbacks import resources as callbacks_resources
from neutron_lib import constants as lib_const
from neutron_lib import rpc as n_rpc
from neutron_lib.utils import net
from os_ken.base import app_manager
from os_ken.lib import ofctl_string
from os_ken.ofproto import ofproto_parser
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging

from neutron.agent.linux.openvswitch_firewall import firewall as ovs_firewall
from neutron.api.rpc.handlers import securitygroups_rpc as sg_rpc
from neutron.objects import ports as port_obj
from neutron.plugins.ml2.drivers.agent import capabilities
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import br_int
from neutron_portcheck.agent.l2.extensions import oskenapp
from neutron_portcheck import constants
from neutron_portcheck import port_check_result


LOG = logging.getLogger(__name__)


class OpenFlowMap:
    def __init__(self):
        self._map = {}

    def put(self, flow):
        key = self.get_key(flow)
        value = self.get_value(flow)
        self._map[key] = value

    def exists(self, flow):
        key = self.get_key(flow)
        value = self.get_value(flow)
        return self._map.get(key) == value

    def remove(self, flow):
        key = self.get_key(flow)
        self._map.pop(key, None)

    def on_update(self, flow):
        if flow.event == oskenapp.NXFME_ADDED:
            self.put(flow)
        elif flow.event == oskenapp.NXFME_DELETED:
            self.remove(flow)
        else:
            # NOTE(akurbatov): neutron doesn't modify openflows
            # FIXME(akurbatov): a manual flows updating is possible using
            # `ovs-ofctl mod-flows` and then we are going to be out of sync
            LOG.warning('Skipping flow update event: %s', flow.event)

    def reset(self):
        self._map.clear()

    @classmethod
    def get_key(cls, flow):
        match = cls._match_dict(flow.match)
        return cls.md5sum(table_id=flow.table_id,
                          priority=flow.priority,
                          match=match)

    @classmethod
    def get_value(cls, flow):
        actions = cls._actions_list(flow.instructions)
        return cls.md5sum(actions=actions)

    @staticmethod
    def md5sum(**values):
        md5 = hashlib.md5(json.dumps(values, sort_keys=True).encode())
        return md5.hexdigest()

    @staticmethod
    def _actions_list(instructions):
        rv = []
        for instruction in instructions:
            if not hasattr(instruction, 'actions'):
                continue
            actions = []
            is_conjuction = False
            for action in instruction.actions:
                action_dict = action.to_jsondict()
                # The 'len' and 'max_len' attrs can result in false positive
                # results for comparison actions. Ignore these attrs:
                # action dict looks like:
                # {'NXActionClass': {'experimenter': 8992, 'len': 16, ...}}
                for key, value in action_dict.items():
                    value.pop('len', None)
                    value.pop('max_len', None)
                    if key == 'NXActionConjunction':
                        is_conjuction = True
                    elif is_conjuction:
                        # From the ovs-fields documentation: "A flow with
                        # conjunction actions may also include note actions for
                        # annotations, but not any other kind of actions."
                        raise ValueError(
                            'non-conjunction and conjunction actions collison')
                    actions.append(action_dict)
            if is_conjuction:
                # From the ovs-fields documentation: "The order of conjunction
                # actions within a list of actions is not significant."
                # And neutron doesn't always keep order. But we need a defined
                # order to calculate a hash sum.
                actions.sort(
                    key=lambda item: item['NXActionConjunction']['id'])
            rv.extend(actions)
        return rv

    @staticmethod
    def _normalize_vlan_vid(vlan_vid):
        '''
        The  OpenFlow  standard  describes this field as consisting of ``12+1’’
        bits. On ingress, its value is 0 if no 802.1Q header  is  present,  and
        otherwise  it holds the VLAN VID in its least significant 12 bits, with
        bit 12 (0x1000 aka OFPVID_PRESENT) also set to 1. The three  most  sig‐
        nificant bits are always zero:

         OXM_OF_VLAN_VID
         <------------->
          3  1     12
        +---+--+--------+
        |   |P |VLAN ID |
        +---+--+--------+
          0
        '''
        value, mask = (
            (vlan_vid, 0x1fff) if isinstance(vlan_vid, int) else vlan_vid)
        mask &= 0x1fff
        value = value & mask
        return value, mask

    @classmethod
    def _match_dict(cls, match):
        rv = dict(match.items())
        for ip_src in ('ipv4_src', 'ipv6_src'):
            ip_src_val = rv.get(ip_src)
            if isinstance(ip_src_val, str):
                addr = netaddr.IPNetwork(ip_src_val)
                rv[ip_src] = (str(addr.ip), str(addr.netmask))

        # NOTE(akurbatov): os-ken doesn't well support a vlan_tci field,
        # i.e. if someone creates a flow with the vlan_tci=0x5000/0xe000
        # match then the os-ken is going to return something like this for
        # such match: OFPMatch(oxm_fields={'field_4194348': 'AAAAAA=='})
        # Fortunately neutron doesn't use vlan_tci functionality (with
        # priorities) and only uses vlan_vid functionality (without
        # priorities). So, we don't take priority into account and equate
        # vlan_tci and vlan_vid to the same match field:
        vlan_tci = rv.pop('vlan_tci', None)
        vlan_vid = rv.pop('vlan_vid', None)
        if vlan_tci is not None:
            if vlan_vid is not None:
                raise ValueError('Both vlan_tci and vlan_vid are provided')
            vlan_vid = vlan_tci
        if vlan_vid is not None:
            rv['vlan_vid'] = cls._normalize_vlan_vid(vlan_vid)
        return rv

class OVSIntegrationBridge(br_int.OVSIntegrationBridge):
    def __init__(self, *args, **kwargs):
        self.of_map = kwargs.pop('of_map')
        self.reports = port_check_result.Reports()
        self.br = self
        super().__init__(*args, **kwargs)

    def __getattribute__(self, attr):
        exc = AttributeError("Method/attr %r is not allowed" % attr)
        # Just to make sure that we don't call ovs flows modification
        # methods:
        forbidden_attrs = ['cleanup_flows', 'run_ofctl']
        if attr in forbidden_attrs:
            raise exc
        if attr.startswith('install') or attr.startswith('uninstall'):
            # 'install_instructions' is override main
            if attr != 'install_instructions':
                raise exc
        return super().__getattribute__(attr)

    def install_instructions(self, instructions,
                             table_id=0, priority=0,
                             match=None, active_bundle=None, **match_kwargs):
        (dp, ofp, ofpp) = self._get_dp()
        match = self._match(ofp, ofpp, match, **match_kwargs)

        jsonlist = ofctl_string.ofp_instruction_from_str(
            ofp, instructions)
        ofp_instructions = ofproto_parser.ofp_instruction_from_jsondict(
            dp, jsonlist)

        flow = oskenapp.OFPFlowUpdate(
            table_id=table_id, priority=priority, match=match,
            instructions=ofp_instructions)
        if not self.of_map.exists(flow):
            match_str = ','.join('%s=%s' % kv for kv in match_kwargs.items())
            msg = ('No flow: table=%s, priority=%s,%s actions=%s',
                   table_id, priority, match_str, instructions)
            self.reports.add(*msg)

    @staticmethod
    def _numeric_ct_state(ct_state):
        CT_BITS = dict([(b, a) for a, b in enumerate([
            "new", "est", "rel", "rpl",
            "inv", "trk", "snat", "dnat"])])
        SENTINEL = '+-'
        ct_state += SENTINEL
        LOG.debug("ct_state: %s", ct_state)
        val = 0
        mask = 0
        while ct_state != SENTINEL:
            pm = ct_state[0]
            ct_state = ct_state[1:]
            nextpos = min([ct_state.find(sep) for sep in ['+', '-']])
            bit = 1 << CT_BITS[ct_state[:nextpos]]
            mask |= bit
            if pm == '+':
                val |= bit
            ct_state = ct_state[nextpos:]
        return (val, mask)

    # Due to ovs-ofctl based 'add_flow' is called during ovs driver
    # initialization, make it to work via native os-ken API to simplify
    # port check plugin logic
    def add_flow(self, **kwargs):
        remap = {
            'dl_dst': 'eth_dst',
            'dl_src': 'eth_src',
            'nw_src': 'ipv4_src',
            'nw_dst': 'ipv4_dst',
            'nw_proto': 'ip_proto',
            'icmp_type': 'icmpv6_type',
            'tp_dst': 'udp_dst',
            'tp_src': 'udp_src',
            'nd_target': 'ipv6_nd_target',
        }
        for key, remap_key in remap.items():
            if key in kwargs:
                kwargs[remap_key] = kwargs.pop(key)
        if 'dl_type' in kwargs:
            kwargs['eth_type'] = int(kwargs.pop('dl_type'), 16)
        if 'dl_vlan' in kwargs:
            dl_vlan = kwargs.pop('dl_vlan')
            if isinstance(dl_vlan, str):
                dl_vlan = int(dl_vlan, 16)
            kwargs['vlan_vid'] = dl_vlan | 0x1000
        if 'ct_mark' in kwargs:
            kwargs['ct_mark'] = int(kwargs.pop('ct_mark'), 16)
        if 'vlan_tci' in kwargs:
            val, mask = kwargs['vlan_tci'].split('/')
            kwargs['vlan_tci'] = (int(val, 16), int(mask, 16))
        if 'actions' in kwargs:
            kwargs['actions'] = kwargs['actions'].replace('strip_vlan', 'pop_vlan')
        if 'ct_state' in kwargs:
            kwargs['ct_state'] = self._numeric_ct_state(kwargs['ct_state'])

        actions = kwargs.pop('actions')
        table_id = kwargs.pop('table')
        self.install_instructions(actions, table_id=table_id, **kwargs)


class OVSFirewallDriver(ovs_firewall.OVSFirewallDriver):

    def __init__(self, integration_bridge):
        super().__init__(integration_bridge)
        # subsciption is not needed:
        callbacks_registry.unsubscribe(
            self._init_firewall_callback,
            callbacks_resources.AGENT,
            callbacks_events.OVS_RESTARTED)

    @property
    def reports(self):
        return self.int_br.reports

    @staticmethod
    def initialize_bridge(int_br):
        return int_br


class PortCheckAgentExtension(l2_extension.L2AgentExtension):
    target = oslo_messaging.Target(version='1.0')

    def __init__(self):
        super(PortCheckAgentExtension, self).__init__()
        capabilities.register(self.init_handler, lib_const.AGENT_TYPE_OVS)

    def initialize(self, connection, driver_type):
        self.of_map = OpenFlowMap()
        self.br_int = OVSIntegrationBridge(
            'br-int',
            os_ken_app=self.agent_api.br_int._app,
            of_map=self.of_map)

        self.start_flow_monitor_app()

        self.create_rpc_conn()
        LOG.info('Port-check agent extenstion loaded')

    def create_rpc_conn(self):
        self._connection = n_rpc.Connection()
        self._connection.create_consumer(constants.TOPIC_PORT_CHECK, [self])
        self._connection.consume_in_threads()

    def init_handler(self, resource, event, trigger, payload=None):
        self.ovs_agent = trigger

    def consume_api(self, agent_api):
        self.agent_api = agent_api

    def start_flow_monitor_app(self):
        app_mgr = app_manager.AppManager.get_instance()
        self.ovs_flow_monitor_app = app_mgr.instantiate(
            oskenapp.OVSFlowMonitorOSKenApp)

        self.ovs_flow_monitor_app.register_event_handler(
            self.of_map.on_update)
        self.ovs_flow_monitor_app.register_revive_handler(
            self._ovs_revived)

        self.ovs_flow_monitor_app.start(self.br_int)

    def _ovs_revived(self):
        LOG.info("Reinitialize openflow monitor after OVS connection revived")
        # get rid of outdated/stale openflows:
        self.of_map.reset()
        self.ovs_flow_monitor_app.start_monitor()

    def ports_check(self, context, **kwargs):
        result_map = collections.defaultdict(port_check_result.PortCheckResult)
        ports = [port_obj.Port.obj_from_primitive(port)
                 for port in kwargs['ports']]
        try:
            self.do_ports_check(context, result_map, ports)
        except Exception as err:
            LOG.exception('do_ports_check error')
            for port in ports:
                reports = result_map[port.id]['openvswitch_agent']
                reports.add('do_ports_check error: %s', err)
        return dict((port_id, result.to_dict())
                    for port_id, result in result_map.items())

    def do_ports_check(self, context, result_map, ports):
        LOG.info('Checking ports (count=%d)', len(ports))

        # Intentionally use SecurityGroupServerRpcApi to honestly pull
        # data from the DB instead of local resource cache:
        sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)
        step = cfg.CONF.rpc_resources_processing_step
        devices = {}
        security_groups = {}
        sg_member_ips = {}
        device_ids = [port.id for port in ports]
        for i in range(0, len(device_ids), step):
            devices_info = sg_plugin_rpc.security_group_info_for_devices(
                context, list(device_ids)[i:i + step])
            devices.update(devices_info['devices'])
            security_groups.update(devices_info['security_groups'])
            sg_member_ips.update(devices_info['sg_member_ips'])

        firewall = OVSFirewallDriver(self.br_int)
        for sg_id, sg_rules in security_groups.items():
            firewall.update_security_group_rules(sg_id, sg_rules)
        for remote_sg_id, member_ips in sg_member_ips.items():
            # There is a bug in security_group_info_for_devices that returns
            # member_ips to the client as a list of lists instead of list of
            # tuples as is declared on the server side. See commit 00298fe6e84
            _member_ips = {}
            for ethertype, addrs in member_ips.items():
                _member_ips[ethertype] = [tuple(addr) for addr in addrs]
            firewall.update_security_group_members(
                remote_sg_id, _member_ips)

        for port in ports:
            firewall.reports.clear()
            reports = result_map[port.id]['firewall']
            try:
                if net.is_port_trusted(port):
                    firewall.process_trusted_ports([port.id])
                else:
                    port_dict = devices.get(port.id)
                    if port_dict:
                        firewall.prepare_port_filter(port_dict)
                    else:
                        reports.add('Cannot find device with port_id %s',
                                    port.id)
                reports.extend(list(firewall.reports))
            except Exception as err:
                if logging.is_debug_enabled(cfg.CONF):
                    LOG.exception('firewall error')
                reports.add('firewall error: %s', err)

    def handle_port(self, context, port):
        # L2AgentExtension.handle_port is abstractmethod.
        # handle_port is not used by this extensions.
        pass

    def delete_port(self, context, port):
        # L2AgentExtension.delete_port is abstractmethod.
        # delete_port is not used by this extensions.
        pass
