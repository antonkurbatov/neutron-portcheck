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
import socket

import eventlet
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as lib_const
from neutron_lib import context as neutron_context
from neutron_lib.db import api as db_api
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils as p_utils
from neutron_lib import rpc as n_rpc
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import loopingcall
import pyroute2

from neutron._i18n import _
from neutron.agent.linux import ip_lib
from neutron.objects import ports as port_obj
from neutron.objects import provisioning_blocks as pb_obj
from neutron.plugins.ml2 import models as ml2_models
from neutron_portcheck import constants
from neutron_portcheck.extensions import port_check
from neutron_portcheck import port_check_result
from neutron_portcheck.services.port_check import prometheus


LOG = logging.getLogger(__name__)

port_check_opts = [
    cfg.IntOpt('ports_check_interval',
               default=120,
               help=_("Interval for checking ports.")),
    cfg.IntOpt('prometheus_port',
               default=6555,
               help=_("Port number to expose metrics in prometheus format.")),
]
cfg.CONF.register_opts(port_check_opts, 'port_check')
CONF = cfg.CONF


def is_primary_node():
    try:
        ha_ip_addr = socket.gethostbyname(constants.HA_HOSTNAME)
    except socket.error as e:
        LOG.error('Cannot resolve %s hostname: %s', constants.HA_HOSTNAME, e)
    else:
        with pyroute2.IPRoute() as ip:
            for pyroute2_addr in ip.get_addr():
                ip_addr = ip_lib.get_attr(pyroute2_addr.dump(), 'IFA_ADDRESS')
                if ip_addr == ha_ip_addr:
                    return True
    return False


class OvsAgentRpcApi(object):
    def __init__(self):
        target = oslo_messaging.Target(topic=constants.TOPIC_PORT_CHECK)
        self.client = n_rpc.get_client(target)

    def ports_check(self, context, ports, host):
        cctxt = self.client.prepare(server=host)
        ports = [port.obj_to_primitive() for port in ports]
        # NOTE: currently port checking is synchronous operation. Maybe
        # it worth to reconsider the approach and make it asynchronous.
        # But for that it will be necessary to introduce the management
        # of the port check operation status.
        return cctxt.call(context, 'ports_check', ports=ports)


class PortCheckPlugin(port_check.PortCheckPluginBase):
    """PortCheckPlugin which supports port checking functionality."""

    supported_extension_aliases = ['port-check']

    def __init__(self):
        self.ovs_agent_rpc = OvsAgentRpcApi()
        self.plugin = directory.get_plugin()
        self.l3_plugin = directory.get_plugin(plugin_constants.L3)
        self.collect_ports_check()
        LOG.info('Port-check plugin loaded')

    def collect_ports_check(self):
        eventlet.spawn(prometheus.start_prometheus_client,
                       CONF.port_check.prometheus_port)
        ports_check_loop = loopingcall.FixedIntervalLoopingCall(
            self.ports_check_loop)
        ports_check_loop.start(
            CONF.port_check.ports_check_interval,
            initial_delay=CONF.port_check.ports_check_interval,
            stop_on_exception=False)

    def ports_check_loop(self):
        if not is_primary_node():
            LOG.debug(
                'Host is not primary node, skip collecting port check info')
            return
        LOG.info('Collecting port check info')
        context = neutron_context.get_admin_context()
        ports = port_obj.Port.get_objects(context)
        ports_map = dict((port.id, port) for port in ports)
        result_map = self.ports_check(context, ports)
        # Update metrics under the lock to avoid
        # reporting partially updated metrics:
        with prometheus.metrics_lock:
            prometheus.port_status_metric.clear()
            for port_id, result in result_map.items():
                port = ports_map[port_id]
                for check_name, reports in result.to_dict().items():
                    metric = prometheus.port_status_metric.labels(
                        port_id=port_id,
                        check=check_name,
                        device_id=port.device_id,
                        device_owner=port.device_owner)
                    metric.set(int(bool(reports)))
        LOG.info('Collecting port check info is done')

    def port_check(self, context, port_id):
        LOG.info('Getting port check info')
        port = port_obj.Port.get_object(context, id=port_id)
        result_map = self.ports_check(context, [port])
        result = result_map[port_id]
        return {
            'port_check': result.to_dict()
        }

    def ports_check(self, context, ports):
        result_map = collections.defaultdict(port_check_result.PortCheckResult)
        self.check_ports_status(context, ports, result_map)
        self.check_provisioning_blocks(context, ports, result_map)
        self.check_l2_ports_bindings(context, ports, result_map)
        self.check_dhcp(context, ports, result_map)
        return result_map

    def check_provisioning_blocks(self, context, ports, result_map):
        pblocks = pb_obj.ProvisioningBlock.get_objects(context)
        entities_map = collections.defaultdict(list)
        for pb in pblocks:
            entities_map[pb.standard_attr_id].append(pb.entity)
        for port in ports:
            reports = result_map[port.id]['provisioning']
            entities = entities_map.get(port.db_obj.standard_attr.id, [])
            for entity in entities:
                reports.add('Port provisioning is not completed by %s agent',
                            entity)

    def check_ports_status(self, context, ports, result_map):
        for port in ports:
            reports = result_map[port.id]['status']
            binding = p_utils.get_port_binding_by_status_and_host(
                port.bindings, lib_const.ACTIVE)
            # Unbinded port has always DOWN status.
            # Report status issue only if the port is binded and not ACTIVE:
            if binding and binding.host and port.status != lib_const.ACTIVE:
                # Even if the port is binded to the host the port with
                # device_owner=network:floatingip_agent_gateway may be in the
                # DOWN state if no VM is connected to the router internal
                # networks:
                if port.device_owner == lib_const.DEVICE_OWNER_AGENT_GW:
                    # FIXME(akurbatov): skip for now a real check of whether
                    # the port should be ACTIVE or can be DOWN to avoid false
                    # positive fails
                    continue
                reports.add('Port status is %s', port.status)

    def _get_agents(self, context, agent_type):
        filters = {'agent_type': [agent_type]}
        agents = self.l3_plugin.get_agent_objects(context, filters=filters)
        agents = [agent for agent in agents if agent.is_active]
        host_agent_map = dict((agent.host, agent) for agent in agents)
        return host_agent_map

    def check_l2_ports_bindings(self, context, ports, result_map):
        ports_by_host = collections.defaultdict(list)

        dvr_bindings = collections.defaultdict(dict)
        router_hosts = collections.defaultdict(list)
        l2_agents = self._get_agents(context, lib_const.AGENT_TYPE_OVS)
        l3_agents = self._get_agents(context, lib_const.AGENT_TYPE_L3)

        # optimization for `openstack port check` CLI command:
        if (len(ports) != 1 or
                ports[0].device_owner == lib_const.DEVICE_OWNER_DVR_INTERFACE):
            with db_api.CONTEXT_READER.using(context):
                query = context.session.query(ml2_models.DistributedPortBinding)
                for binding in query.all():
                    dvr_bindings[binding.port_id][binding.host] = binding

            for host, agent in l3_agents.items():
                router_ids = self.l3_plugin._get_router_ids_for_agent(
                    context, agent, None)
                for router_id in router_ids:
                    router_hosts[router_id].append(host)

        for port in ports:
            reports = result_map[port.id]['binding']
            inactive_binding = p_utils.get_port_binding_by_status_and_host(
                port.bindings, lib_const.INACTIVE)
            if inactive_binding:
                reports.add('INACTIVE port binding on host %s',
                            inactive_binding.host)
            binding = p_utils.get_port_binding_by_status_and_host(
                port.bindings, lib_const.ACTIVE)
            if not binding:
                # ACTIVE port binding should always present.
                # If not then something critical happened.
                reports.add('ACTIVE port binding not found')
                continue

            bindings = []
            if port.device_owner == lib_const.DEVICE_OWNER_DVR_INTERFACE:
                for host in router_hosts[port.device_id]:
                    binding = dvr_bindings[port.id].get(host)
                    if not binding:
                        reports.add('DVR port is not bound on host %s', host)
                    elif binding.status != lib_const.ACTIVE:
                        reports.add('DVR port binding is %s on host %s',
                                    binding.status, host)
                    else:
                        bindings.append(binding)
            else:
                bindings.append(binding)

            for binding in bindings:
                # Skip bindings without host
                if not binding.host:
                    continue
                # Neutron ovs agent may emit log errors if the device_id of the
                # port is "reserved_dhcp_port" because the ovs port has been
                # removed from the br-int bridge. We report this issue in DHCP
                # port checking step and skip it here:
                if port.device_id == lib_const.DEVICE_ID_RESERVED_DHCP_PORT:
                    continue
                if binding.vif_type == portbindings.VIF_TYPE_UNBOUND:
                    reports.add('Port is unbound')
                elif binding.vif_type == portbindings.VIF_TYPE_BINDING_FAILED:
                    reports.add('Port binding failed')
                elif binding.vif_type != portbindings.VIF_TYPE_OVS:
                    reports.add('Port binding has unsupported vif_type: %s',
                              binding.vif_type)
                else:
                    # Even if the port is binded to the host it can be in the
                    # DOWN state in some cases, i.e. floatingip_agent_gateway
                    # port. If the port is in the DOWN state there is no sense
                    # in checking the firewall logic: such a check will most
                    # likely fail or generate warning in the neutron-ovs-agent
                    if port.status != lib_const.ACTIVE:
                        continue
                    ports_by_host[binding.host].append(port)

        for host, ports in ports_by_host.items():
            if host not in l2_agents:
                # L2 agent is not alive:
                continue
            ovs_result = self.ovs_agent_rpc.ports_check(context, ports, host)
            for port in ports:
                result_map[port.id].update(ovs_result[port.id])

    def check_dhcp(self, context, ports, result_map):
        for port in ports:
            if port.device_owner != lib_const.DEVICE_OWNER_DHCP:
                continue
            # Currently just check reserved dhcp ports, it's unacceptable
            # if such port is found:
            if port.device_id == lib_const.DEVICE_ID_RESERVED_DHCP_PORT:
                result_map[port.id]['dhcp'].add(
                    '%r device_id is unacceptable', port.device_id)
