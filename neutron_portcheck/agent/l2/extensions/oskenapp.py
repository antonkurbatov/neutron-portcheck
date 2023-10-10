import struct

from oslo_log import log as logging
from os_ken.base import app_manager
from os_ken.controller import handler
from os_ken.controller import ofp_event
from os_ken.lib.pack_utils import msg_pack_into
from os_ken.ofproto import ofproto_parser
from os_ken.ofproto import ofproto_v1_3
from os_ken.ofproto import ofproto_v1_3_parser
from os_ken import utils

# include/openvswitch/ofp-msgs.h
#    /* ONFST 1.3 (1870): uint8_t[8][]. */
#    OFPRAW_ONFST13_FLOW_MONITOR_REPLY,
FLOW_MONITOR_REPLY = 1870

OFPMT_OXM = 1

# include/openflow/nicira-ext.h
NXFME_ADDED = 0
NXFME_DELETED = 1
NXFME_MODIFIED = 2
NXFME_EVENTS = [NXFME_ADDED, NXFME_DELETED, NXFME_MODIFIED]

NX_FLOW_UPDATE_FULL_PACK_STR = '!HHHHHHHBBQ'
NX_FLOW_UPDATE_FULL_SIZE = 24
assert (struct.calcsize(NX_FLOW_UPDATE_FULL_PACK_STR) ==
        NX_FLOW_UPDATE_FULL_SIZE)


LOG = logging.getLogger(__name__)


class OVSFlowMonitorOSKenApp(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _event_handlers = []
    _revive_handlers = []

    def register_event_handler(self, caller):
        self._event_handlers.append(caller)

    def register_revive_handler(self, caller):
        self._revive_handlers.append(caller)

    @handler.set_ev_cls(ofp_event.EventOFPExperimenterStatsReply,
                        handler.MAIN_DISPATCHER)
    def flow_monitor_reply_handler(self, ev):
        msg_body = ev.msg.body
        if msg_body.exp_type != FLOW_MONITOR_REPLY:
            return

        offset = 0
        length = len(msg_body.data)
        while length:
            flow_update = OFPFlowUpdate.parser(msg_body.data, offset=offset)
            length -= flow_update.length
            offset += flow_update.length
            for caller in self._event_handlers:
                caller(flow_update)

    @handler.set_ev_cls(ofp_event.EventOFPStateChange, handler.DEAD_DISPATCHER)
    def handle_dead(self, ev):
        if self._datapath_id and self._datapath_id == ev.datapath.id:
            LOG.info('Datapath %s is dead', self._datapath_id)

    @handler.set_ev_cls(ofp_event.EventOFPStateChange, handler.MAIN_DISPATCHER)
    def handle_main(self, ev):
        if self._datapath_id and self._datapath_id == ev.datapath.id:
            LOG.info('Datapath %s is alive', self._datapath_id)
            for caller in self._revive_handlers:
                caller()

    def start(self, bridge):
        super().start()
        self.bridge = bridge
        self._datapath = None
        self._datapath_id = None
        self.start_monitor()

    def start_monitor(self):
        dp, ofp, ofpp = self.bridge._get_dp()
        if self._datapath and self._datapath == dp:
            LOG.info('Skipping monitor request for datapath %s as it was '
                     'already started', self._datapath_id)
            return

        self._datapath = dp
        self._datapath_id = self._datapath.id
        flags = (ofp.ONFFMF_INITIAL |
                 ofp.ONFFMF_ADD |
                 ofp.ONFFMF_DELETE |
                 ofp.ONFFMF_MODIFY |
                 ofp.ONFFMF_ACTIONS |
                 ofp.ONFFMF_OWN)
        fm_request = ONFFlowMonitorRequest(0, flags)
        msg = ofpp.ONFFlowMonitorStatsRequest(dp, 0, body=[fm_request])
        self.bridge._send_msg(msg)


class ONFFlowMonitorRequest(ofproto_v1_3_parser.ONFFlowMonitorRequest):
    def serialize(self):
        # The upstream ONFFlowMonitorRequest sends a `match` buffer only if the
        # `match` has any non-empty fields and for the `empty` OFPMatch() (i.e.
        # for matching all flow changes) it doesn't put such a match in the
        # request payload. This causes a fail on the ovs-vswitchd side:
        #
        # ofp_errors|ERR|cannot encode error for unknown OpenFlow version 0x00
        # ofp_errors|ERR|cannot encode OFPBMC_BAD_LEN for OpenFlow 1.0
        #
        # Here we repeat the upstream logic but without ignoring the `empty`
        # match.
        match = self.match
        bin_match = bytearray()
        ofp_match_len = match.serialize(bin_match, 0)

        buf = bytearray()
        msg_pack_into(ofproto_v1_3.ONF_FLOW_MONITOR_REQUEST_PACK_STR,
                      buf, 0,
                      self.id, self.flags, ofp_match_len,
                      self.out_port, self.table_id)
        buf += bin_match
        return buf


class OFPFlowUpdate(ofproto_parser.StringifyMixin):
    def __init__(self, event=None, reason=None, priority=None,
                 idle_timeout=None, hard_timeout=None, table_id=None,
                 cookie=None, match=None, instructions=None, length=None):
        super(OFPFlowUpdate, self).__init__()
        self.event = event
        self.reason = reason
        self.priority = priority
        self.idle_timeout = idle_timeout
        self.hard_timeout = hard_timeout
        self.table_id = table_id
        self.cookie = cookie
        self.match = match
        self.instructions = instructions
        self.length = length

    @classmethod
    def parser(cls, buf, offset):
        flow_update = cls()

        (flow_update.length, flow_update.event, flow_update.reason,
         flow_update.priority, flow_update.idle_timeout,
         flow_update.hard_timeout, match_len, flow_update.table_id,
         pad, flow_update.cookie) = (struct.unpack_from(
            NX_FLOW_UPDATE_FULL_PACK_STR, buf, offset=offset))
        pull_offset = NX_FLOW_UPDATE_FULL_SIZE

        flow_update.match = ofproto_v1_3_parser.OFPMatch.parser(
            buf, offset + pull_offset)
        pull_offset += utils.round_up(flow_update.match.length, 8)

        inst_length = flow_update.length - pull_offset
        instructions = []
        while inst_length:
            inst = ofproto_v1_3_parser.OFPInstruction.parser(
                buf, offset + pull_offset)
            instructions.append(inst)
            pull_offset += inst.len
            inst_length -= inst.len

        flow_update.instructions = instructions
        return flow_update
