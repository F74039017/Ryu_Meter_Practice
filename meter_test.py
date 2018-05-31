# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib import hub
from ryu.lib.packet import ipv4, udp
from json import dump, dumps

from ryu.app.rest_router import ipv4_text_to_int, ipv4_int_to_text
# import switches ryu app indirectly
from ryu.topology.api import get_switch, get_link, get_host
import pyjsonrpc
import netifaces as ni

# Const.
IFACE_NAME = 'eno1'
RPC_PORT = 5656
FLOW_PRIORITY = 200 # this should be higher than SimpleSwitch13

class METER_TEST(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(METER_TEST, self).__init__(*args, **kwargs)
        self.rpc = RPCServer(app=self)
        self.qos_rule = [] # [(meter_id, dst_ip, dst_port, max_rate...]

        self.dps = None # reference to switches app. Do not modify this variable!!
        hub.spawn(self.get_dps_ref)

        # mimic SimpleSwitch13
        # XXX: Although this will cause duplicated code, we can't guarantee that SimpleSiwtch13 processes packet_in before this app.
        self.mac_to_port = {}
        self.ip_to_mac = {}

    ####################################
    #  GET REFERENCE FROM OTHER BRICK  #
    ####################################

    def get_dps_ref(self):
        while True:
            brick = app_manager.lookup_service_brick('switches')
            if brick:
                self.dps = brick.dps
                print 'Get dps reference from switches app'
                break
            hub.sleep(100)

    ###########################
    #  RYU EVENTS & ADD FLOW  # 
    ###########################

    def add_meter_instance(self, datapath, meter_id, max_rate):

        # TODO: if the meter id exist, then modify the meter instance istead of adding it

        # safety check
        if None in [datapath, meter_id, max_rate]:
            raise Exception('Null parameter!!')

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        print "\033[1;34;49mAdd Meter {}: max_rate {} kbps\033[0;37;49m".format(meter_id, max_rate)

        bands = [parser.OFPMeterBandDrop(int(max_rate))]
        mod = parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS, meter_id=int(meter_id), bands=bands)

        datapath.send_msg(mod)

    def add_qos_rule_flow(self, datapath, dst_ip, dst_port, meter_id, buffer_id=None):

        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()

        # only match by dst. info.
        match.set_ipv4_dst(ipv4_text_to_int(dst_ip.encode('utf8')))
        match.set_udp_dst(int(dst_port))
        match.set_dl_type(0x800) # prereq of ipv4
        match.set_ip_proto(0x11) # prereq of udp

        # SimpleSwitch13 forwarding logic
        if self.ip_to_mac.get(dst_ip, None) in self.mac_to_port.get(dpid, {}):
            print "\033[1;34;49mAdd QoS flow: dst_ip {}, dst_port {} => Meter {}\033[0;37;49m".format(dst_ip, dst_port, meter_id)
            out_port = self.mac_to_port[dpid][self.ip_to_mac[dst_ip]]
        else:
            return

        # Go meter before apply actions
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionMeter(int(meter_id), ofproto.OFPIT_METER),
                parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=FLOW_PRIORITY, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=FLOW_PRIORITY,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip = pkt.get_protocol(ipv4.ipv4)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst_mac = eth.dst
        src_mac = eth.src

        # mimic SimpleSwitch13
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        if not ip:
            return

        dst_ip = ip.dst
        src_ip = ip.src

        self.ip_to_mac[dst_ip] = dst_mac # dst_ip is string
        self.ip_to_mac[src_ip] = src_mac

        # check if there is an qos_rule matching
        for _meter_id, _dst_ip, _dst_port, _max_rate in self.qos_rule:
            # TODO: check port
            if _dst_ip == dst_ip:
                app.add_meter_instance(datapath, _meter_id, _max_rate)
                app.add_qos_rule_flow(dp, dst_ip, dst_port, meter_id)

def MakeHandlerClass(kwargs):
    class CustomHandler(pyjsonrpc.HttpRequestHandler):

        @pyjsonrpc.rpcmethod
        def add_meter_rule(self, cmd):

            meter_id = cmd['meter_id']
            dst_ip = cmd['dst_ip']
            dst_port = cmd['dst_port']
            max_rate = cmd['max_rate']

            app = kwargs['app']

            # debug
            print dumps(cmd, sort_keys = True, indent = 4)

            # record rule
            app.qos_rule.append((meter_id, dst_ip, dst_port, max_rate))

            # try to add qos rule if ip appeared in packet_in
            for dp in app.dps.values():
                app.add_meter_instance(dp, meter_id, max_rate)
                app.add_qos_rule_flow(dp, dst_ip, dst_port, meter_id)

            return "OK\n"

    return CustomHandler

class RPCServer():
    def __init__(self, **kwargs):
        HandlerClass = MakeHandlerClass(kwargs=kwargs)
        ni.ifaddresses(IFACE_NAME)
        self.ip = ni.ifaddresses(IFACE_NAME)[ni.AF_INET][0]['addr']
        self.httpServer = pyjsonrpc.ThreadingHttpServer(server_address = (self.ip, RPC_PORT), RequestHandlerClass = HandlerClass)
        self.startThread = hub.spawn(self.start)

    def start(self):
        print 'Start RPC Server'
        print '\033[1;32;49mURL: {0}:{1}\033[0;37;49m'.format(self.ip, RPC_PORT)
        self.httpServer.serve_forever()
