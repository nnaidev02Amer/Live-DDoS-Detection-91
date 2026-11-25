"""SDN controller interface.

Only SimulatedController is implemented. It remembers rules in memory and never
talks to a network. A future Ryu controller class should subclass SDNController,
send the rules to real switches and set is_live = True only after the switch has
confirmed them.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass

ETH_TYPE_IPV4 = 0x0800
RULE_PRIORITY = 100     # above the learning switch's priority 1 forwarding rules
BLOCK_SECONDS = 120     # same hard timeout as block_port() in switchm.py


@dataclass(frozen=True)
class FlowRule:
    """Drop IPv4 traffic of one protocol from one source to one destination."""
    datapath_id: int
    ip_src: str
    ip_dst: str
    ip_proto: int
    priority: int = RULE_PRIORITY
    hard_timeout: int = BLOCK_SECONDS

    @property
    def key(self):
        return (self.datapath_id, self.ip_src, self.ip_dst, self.ip_proto)


def to_ryu_flow_entry(rule):
    """Body for Ryu's ofctl_rest API: POST /stats/flowentry/add.

    An empty action list means "drop" in OpenFlow. This function only builds the
    message; nothing is sent.
    """
    return {
        "dpid": rule.datapath_id,
        "priority": rule.priority,
        "hard_timeout": rule.hard_timeout,
        "match": {"eth_type": ETH_TYPE_IPV4, "ipv4_src": rule.ip_src,
                  "ipv4_dst": rule.ip_dst, "ip_proto": rule.ip_proto},
        "actions": [],
    }


def to_ovs_command(rule):
    """Equivalent Open vSwitch command (switch dpid 1 is s1 in the Mininet topology)."""
    return (f'sudo ovs-ofctl -O OpenFlow13 add-flow s{rule.datapath_id} '
            f'"hard_timeout={rule.hard_timeout},priority={rule.priority},ip,'
            f'nw_src={rule.ip_src},nw_dst={rule.ip_dst},nw_proto={rule.ip_proto},actions=drop"')


class SDNController(ABC):
    """What the mitigation engine needs from any controller."""

    name = "abstract"
    is_live = False     # True only for a controller that changes real switches

    @abstractmethod
    def install_rule(self, rule):
        """Install a drop rule."""

    @abstractmethod
    def remove_rule(self, rule):
        """Remove a drop rule."""

    @abstractmethod
    def list_rules(self):
        """Rules currently installed."""


class SimulatedController(SDNController):
    """In-memory stand-in that works on Windows. No packet is ever blocked."""

    name = "Simulated controller"
    is_live = False

    def __init__(self):
        self._rules = {}

    def install_rule(self, rule):
        self._rules[rule.key] = rule

    def remove_rule(self, rule):
        self._rules.pop(rule.key, None)

    def list_rules(self):
        return list(self._rules.values())
