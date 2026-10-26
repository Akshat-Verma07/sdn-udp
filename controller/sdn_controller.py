"""
sdn_controller.py - Ryu (OpenFlow 1.3) controller for the diamond topology.

D1 scope (this file):
  * Proactively install forwarding flows for the PRIMARY path
        h1 - s1 - s2 - s4 - h2
    as soon as each switch connects (no reactive packet-in learning, so there
    is no flooding and no loops).
  * Detect link failures through OpenFlow PortStatus messages and REROUTE
    traffic onto the BACKUP path  h1 - s1 - s3 - s4 - h2.
  * Listen on UDP :9999 for the sender's "app_stats" datagrams (retransmission
    count, RTT, ...).  In D1 they are only logged; D2 will use them to decide
    that a path is degraded even when no link has gone down.

Run:
    ryu-manager controller/sdn_controller.py
(Mininet then connects to 127.0.0.1:6653, the default OpenFlow port.)

Topology port map (must match topology/diamond_topo.py):
    s1: 1=h1   2=s2   3=s3
    s2: 1=s1   2=s4
    s3: 1=s1   2=s4
    s4: 1=h2   2=s2   3=s3
"""

import json
import os
import socket

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3

H1_IP, H2_IP = "10.0.0.1", "10.0.0.2"
APP_STATS_PORT = 9999
APP_STATS_UNIX = "/tmp/sdn_app_stats.sock"   # reachable from Mininet hosts

# For each named path: {dpid: (out_port towards h2, out_port towards h1)}.
# 'fwd' = traffic destined to h2, 'rev' = traffic destined to h1.
PATHS = {
    "primary": {
        1: {"fwd": 2, "rev": 1},      # s1: to h2 via s2 (port 2); to h1 via host port 1
        2: {"fwd": 2, "rev": 1},      # s2: to h2 via s4; to h1 via s1
        4: {"fwd": 1, "rev": 2},      # s4: to h2 via host port 1; to h1 via s2 (port 2)
    },
    "backup": {
        1: {"fwd": 3, "rev": 1},      # s1: to h2 via s3 (port 3)
        3: {"fwd": 2, "rev": 1},      # s3: to h2 via s4; to h1 via s1
        4: {"fwd": 1, "rev": 3},      # s4: to h1 via s3 (port 3)
    },
}

# Which (dpid, port) pairs belong to each path.  If one of them goes down the
# path is considered broken.
PATH_LINK_PORTS = {
    "primary": {(1, 2), (2, 1), (2, 2), (4, 2)},
    "backup":  {(1, 3), (3, 1), (3, 2), (4, 3)},
}

FLOW_PRIORITY = 100


class DiamondController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DiamondController, self).__init__(*args, **kwargs)
        self.datapaths = {}               # dpid -> datapath object
        self.active_path = "primary"      # path currently carrying traffic
        self.down_ports = set()           # (dpid, port) known to be down
        self.last_app_stats = {}          # latest stats from the sender
        # Background green-thread that receives app stats from the sender.
        hub.spawn(self._app_stats_listener, "udp")
        hub.spawn(self._app_stats_listener, "unix")

    # ------------------------------------------------------------------
    # Switch connects: install table-miss + forwarding flows
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        self.logger.info("switch s%d connected", dp.id)
        # Table-miss: anything unmatched is dropped (no actions).  We do not
        # want unknown traffic flooding around the loop.
        self._add_flow(dp, 0, dp.ofproto_parser.OFPMatch(), [])
        # Install the flows of whichever path is active.
        self._install_path(self.active_path, only_dpid=dp.id)

    # ------------------------------------------------------------------
    # Link failure detection
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        port_no = msg.desc.port_no
        # A port is unusable if the admin brought it down or the link is down.
        is_down = bool(msg.desc.state & ofp.OFPPS_LINK_DOWN) or \
                  bool(msg.desc.config & ofp.OFPPC_PORT_DOWN)
        key = (dp.id, port_no)

        if is_down and key not in self.down_ports:
            self.down_ports.add(key)
            self.logger.warning("PORT DOWN  s%d port %d", dp.id, port_no)
            self._reevaluate_path()
        elif not is_down and key in self.down_ports:
            self.down_ports.discard(key)
            self.logger.info("PORT UP    s%d port %d", dp.id, port_no)
            # (D2: optionally fail back to the primary path.)

    def _path_is_broken(self, name):
        return bool(PATH_LINK_PORTS[name] & self.down_ports)

    def _reevaluate_path(self):
        """If the active path has a dead link and the other is healthy, switch."""
        if not self._path_is_broken(self.active_path):
            return
        other = "backup" if self.active_path == "primary" else "primary"
        if self._path_is_broken(other):
            self.logger.error("both paths are broken - nothing to reroute to")
            return
        self.logger.warning("REROUTE: %s -> %s", self.active_path, other)
        self.active_path = other
        self._install_path(other)

    # ------------------------------------------------------------------
    # Flow installation helpers
    # ------------------------------------------------------------------
    def _install_path(self, name, only_dpid=None):
        """Install forwarding flows for path `name` on its switches.

        Flows use the SAME match and priority for every path, and OpenFlow
        OFPFC_ADD overwrites an existing entry with an identical match, so
        installing the backup path simply replaces the primary path's actions.
        """
        for dpid, ports in PATHS[name].items():
            if only_dpid is not None and dpid != only_dpid:
                continue
            dp = self.datapaths.get(dpid)
            if dp is None:
                continue
            parser = dp.ofproto_parser
            # Traffic to h2
            self._add_flow(dp, FLOW_PRIORITY, parser.OFPMatch(
                eth_type=0x0800, ipv4_dst=H2_IP),
                [parser.OFPActionOutput(ports["fwd"])])
            # Traffic to h1
            self._add_flow(dp, FLOW_PRIORITY, parser.OFPMatch(
                eth_type=0x0800, ipv4_dst=H1_IP),
                [parser.OFPActionOutput(ports["rev"])])
        self.logger.info("installed %s path flows", name)

    def _add_flow(self, dp, priority, match, actions):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=priority,
                                      match=match, instructions=inst,
                                      command=ofp.OFPFC_ADD))

    # ------------------------------------------------------------------
    # Application -> SDN feedback channel
    # ------------------------------------------------------------------
    def _app_stats_listener(self, kind):
        """Receive JSON stats datagrams from the sender (UDP :9999).

        This is the Socket-SDN integration hook: the application tells the
        controller how the transfer is doing (retransmissions, RTT).
        """
        if kind == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", APP_STATS_PORT))
        else:
            # Mininet hosts live in separate network namespaces, so they cannot
            # reach the controller's 127.0.0.1.  A Unix socket is a file and
            # the filesystem is shared, so it works from any host.
            if os.path.exists(APP_STATS_UNIX):
                os.unlink(APP_STATS_UNIX)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.bind(APP_STATS_UNIX)
            os.chmod(APP_STATS_UNIX, 0o777)
        sock.setblocking(False)
        while True:
            try:
                data, _addr = sock.recvfrom(4096)
            except BlockingIOError:
                hub.sleep(0.2)            # yield to other green threads
                continue
            try:
                msg = json.loads(data.decode())
            except ValueError:
                continue
            if msg.get("type") == "app_stats":
                self.last_app_stats = msg
                self.logger.info(
                    "app_stats: acked=%s/%s retx=%s timeouts=%s srtt=%s",
                    msg.get("acked"), msg.get("total"),
                    msg.get("retransmissions"), msg.get("timeouts"),
                    msg.get("srtt"))
