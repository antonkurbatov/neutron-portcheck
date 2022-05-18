from neutron.db import provisioning_blocks
from neutron.objects import ports as port_obj
from neutron.objects import provisioning_blocks as pb_obj
from neutron.objects import subnet as subnet_obj
from neutron_lib import constants as lib_const
from neutron_lib import rpc as n_rpc
from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import resources
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils as p_utils
from oslo_log import log as logging
import oslo_messaging

from neutron_portcheck import exceptions
from neutron_portcheck import utils
from neutron_portcheck.agent.l2.extensions import constants
from neutron_portcheck.extensions import port_check


LOG = logging.getLogger(__name__)


class OvsAgentRpcApi(object):
    def __init__(self):
        target = oslo_messaging.Target(topic=constants.PORT_CHECK_PLUGIN)
        self.client = n_rpc.get_client(target)

    def port_check(self, context, port, host):
        cctxt = self.client.prepare(server=host)
        port_primitive = port.obj_to_primitive()
        # NOTE: currently port checking is synchronous operation. Maybe
        # it worth to reconsider the approach and make it asynchronous.
        # But for that it will be necessary to introduce the management
        # of the port check operation status.
        return cctxt.call(context, 'port_check', port=port_primitive)


class PortCheckPlugin(port_check.PortCheckPluginBase):
    """PortCheckPlugin which supports port checking functionality."""
    
    supported_extension_aliases = ['port-check']

    def __init__(self):
        self.ovs_agent_rpc = OvsAgentRpcApi()
        self.plugin = directory.get_plugin()
        LOG.info('Port-check plugin loaded')

    def port_check(self, context, port_id):
        result = {}
        port = port_obj.Port.get_object(context, id=port_id)

        result['bindings'] = self._check_port_bindings(context, port)
        result['provisioning_blocks'] = (
            self._check_provisioning_blocks(context, port))
        result['port_status'] = self._check_port_status(context, port)
        result['openvswitch_agent'] = self._check_ovs_agent(context, port)

        return result

    def _check_port_bindings(self, context, port):
        errs = []
        binding = p_utils.get_port_binding_by_status_and_host(
            port.bindings, lib_const.ACTIVE)
        if (binding.host and
                binding.vif_type == portbindings.VIF_TYPE_BINDING_FAILED):
            errs.append('Port binding failed (host=%s)' % binding.host)
        return errs

    def _check_provisioning_blocks(self, context, port):
        errs = []
        standard_attr_id = provisioning_blocks._get_standard_attr_id(
            context, port.id, resources.PORT)
        
        def _check_entity(entity):
            if pb_obj.ProvisioningBlock.objects_exist(
                    context, standard_attr_id=standard_attr_id, entity=entity):
                errs.append(
                    'Port provisioning is not completed by %r entity' % entity)
        
        for fixed_ip in port.fixed_ips:
            subnet_id = fixed_ip.subnet_id
            subnet = subnet_obj.Subnet.get_object(context, id=subnet_id)
            if subnet.enable_dhcp:
                _check_entity(provisioning_blocks.DHCP_ENTITY)
                break

        _check_entity(provisioning_blocks.L2_AGENT_ENTITY)
        return errs

    def _check_port_status(self, context, port):
        errs = []
        if port.status != lib_const.ACTIVE:
            errs.append('Port is not ACTIVE')
        return errs

    @utils.safe_func
    def _check_ovs_agent(self, context, port):
        binding = p_utils.get_port_binding_by_status_and_host(
            port.bindings, lib_const.ACTIVE)
        host = binding.host
        if not host:
            raise exceptions.PortCheckError('No host assigned to port')

        agents = self.plugin.get_agents(
            context, filters={'agent_type': [lib_const.AGENT_TYPE_OVS],
                              'host': [host]})
        if not agents:
            raise exceptions.PortCheckError('Agent not found')
        if len(agents) > 1:
            raise exceptions.PortCheckError('Multiple agents found')
        if not agents[0]['alive']:
            return exceptions.PortCheckError('Agent is dead: %s' % host)
        if binding.vif_type != portbindings.VIF_TYPE_OVS:
            raise exceptions.PortCheckError('binding is not ovs type')
        return self.ovs_agent_rpc.port_check(context, port, host)
