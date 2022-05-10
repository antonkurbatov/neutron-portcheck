import textwrap
import traceback

from neutron.agent.linux.openvswitch_firewall import firewall as ovs_firewall
from neutron.agent.linux.openvswitch_firewall import iptables
from neutron.api.rpc.handlers import securitygroups_rpc as sg_rpc
from neutron.objects import ports as port_obj
from neutron.plugins.ml2.drivers.agent import capabilities
from neutron_lib import constants as lib_const
from neutron_lib import rpc as n_rpc
from neutron_lib.agent import l2_extension
from neutron_lib.utils import net
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging

from neutron_portcheck import exceptions
from neutron_portcheck import utils
from neutron_portcheck.agent.l2.extensions import constants
from neutron_portcheck.agent.l2.extensions import flows


LOG = logging.getLogger(__name__)


class BridgeWrapper(object):
    def __init__(self, bridge):
        self._bridge = bridge
        self._flows = None
        self._errors = []

    def __getattr__(self, name):
        allowed_methods = ['db_get_val',
                           'get_port_ofport',
                           'get_vif_port_by_id']
        if name not in allowed_methods:
            raise AttributeError('%s is no allowed' % name)
        return getattr(self._bridge, name)

    @property
    def flows(self):
        if not self._flows:
            flows_raw = self._bridge.dump_all_flows()
            self._flows = flows.Flows(flows_raw)
        return self._flows

    def get_errors(self):
        return self._errors

    @staticmethod
    def _flow_string(**params):
        priority = params.pop('priority')
        actions = params.pop('actions')
        rv = 'table=%d' % params.pop('table')
        for key, value in params.items():
            if key != 'protocol':
                value = '%s=%s' % (key, value)
            rv += ',%s' % value
        rv += ' [priority=%s,actions=%s]' % (priority, actions)
        return rv

    def format_frame(self):
        for frame in traceback.extract_stack()[::-1]:
            filename = frame[0]
            if 'openvswitch_firewall/firewall' in filename:
                frame = traceback.format_list([frame])[0]
                return textwrap.dedent(frame.strip('\n'))
                
    def add_flow(self, **kwargs):
        params = flows.Flows.normalize_params(**kwargs)
        flows_list = self.flows.filter_flows(**params)

        err = None
        if not flows_list:
            err = 'Flow not found'
        elif len(flows_list) > 1:
            LOG.info('Flows:\n%s', '\n'.join(flows_list))
            err = 'Found %d flows' % len(flows_list)
        if err:
            self._errors.append({'error': err,
                                 'flow': self._flow_string(**params),
                                 'frame': self.format_frame()})


class BundledBridgeWrapper(object):
    def __init__(self, bridge):
        self.br = BridgeWrapper(bridge)


class OVSFirewallDriver(ovs_firewall.OVSFirewallDriver):    
    def __init__(self, integration_bridge):
        self.permitted_ethertypes = cfg.CONF.SECURITYGROUP.permitted_ethertypes
        self.int_br = BundledBridgeWrapper(integration_bridge)
        self.sg_port_map = ovs_firewall.SGPortMap()
        self.conj_ip_manager = ovs_firewall.ConjIPFlowManager(self)
        self.iptables_helper = iptables.Helper(self.int_br.br)

    def _add_flow(self, **kwargs):
        kwargs = self.int_br.br.add_flow(**kwargs)

    def get_errors(self):
        return self.int_br.br.get_errors()


class PortCheckAgentExtension(l2_extension.L2AgentExtension):
    target = oslo_messaging.Target(version='1.0')

    def __init__(self):
        super(PortCheckAgentExtension, self).__init__()
        capabilities.register(self.init_handler, lib_const.AGENT_TYPE_OVS)

    def initialize(self, connection, driver_type):
        self._connection = n_rpc.Connection()
        srv = self._connection.create_consumer(constants.PORT_CHECK_PLUGIN,
                                               [self], fanout=True)
        self._connection.consume_in_threads()
        LOG.info('Port-check agent extenstion loaded')

    def init_handler(self, resource, event, trigger, payload=None):
        self.ovs_agent = trigger

    def consume_api(self, agent_api):
        self.agent_api = agent_api

    def port_check(self, context, **kwargs):
        try:
            rv = self._port_check(context, **kwargs)
        except exceptions.PortCheckError as err:
            return [{'error': str(err)}]
        except Exception as err:
            LOG.exception('port_check failed')
            return [{'error': str(err)}]

        return rv

    @utils.safe_func
    def port_check(self, context, **kwargs):
        port_primitive = kwargs['port']
        port = port_obj.Port.clean_obj_from_primitive(port_primitive)
        if net.is_port_trusted(port):
            raise exceptions.PortCheckError(
                'Trusted port check not implemented yet')
        # Intentionally use SecurityGroupServerRpcApi to honestly pull
        # data from the DB.
        sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi('q-plugin')
        devices_info = (
            sg_plugin_rpc.security_group_info_for_devices(context, [port.id]))
        devices = devices_info['devices']
        security_groups = devices_info['security_groups']
        sg_member_ips = devices_info['sg_member_ips']

        port_dict = devices.get(port.id)
        if not port_dict:
            raise exceptions.PortCheckError(
                'Cannot find device by port_id: %s' % port.id)

        firewall = OVSFirewallDriver(self.agent_api.br_int)
        for sg_id, sg_rules in security_groups.items():
            firewall.update_security_group_rules(sg_id, sg_rules)
        for remote_sg_id, member_ips in sg_member_ips.items():
            firewall.update_security_group_members(
                remote_sg_id, member_ips)
        
        firewall._initialize_firewall()
        firewall.prepare_port_filter(port_dict)
        return firewall.get_errors()

    def handle_port(self, context, port):
        # L2AgentExtension.handle_port is abstractmethod.
        # handle_port is not used by this extensions.
        pass

    def delete_port(self, context, port):
        # L2AgentExtension.delete_port is abstractmethod.
        # delete_port is not used by this extensions.
        pass
