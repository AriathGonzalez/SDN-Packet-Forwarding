'''
[h10@10.0.1.10/24]--{s1}--\
[h20@10.0.2.20/24]--{s2}--{cores21}--{dcs31}--[serv1@10.0.4.10/24]
[h30@10.0.3.30/24]--{s3}--/   |
                              |
                  [hnotrust1@172.16.10.100/24]

- Allow traffic to be transmitted btwn all hosts
- (s1,s2,s3,dcs31) will use of.OFPP_FLOOD
- cores21 will specify specific ports for all IP
- block (drop) all IP traffic from Untrusted Host to Server 1
- block (drop) all ICMP traffic from Untrusted Host

All nodes should be able to communicate EXCEPT
- hnotrust1 cannot send ICMP traffic to h10,h20,h30, or serv1
- hnotrust1 cannot send any IP traffic to serv1
'''

from pox.core import core
import pox.openflow.libopenflow_01 as of

# Import IP and Ethernet address classes
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr

# Get the logger for the core component
log = core.getLogger()

# Define constants for Ethernet type and ICMP protocol number
IPV4 = 0x0800
ICMP_PROTO = 1

# Statically allocate IP addresses and MAC addresses for hosts
IPS = {
  "h10" : ("10.0.1.10", '00:00:00:00:00:01'),
  "h20" : ("10.0.2.20", '00:00:00:00:00:02'),
  "h30" : ("10.0.3.30", '00:00:00:00:00:03'),
  "serv1" : ("10.0.4.10", '00:00:00:00:00:04'),
  "hnotrust" : ("172.16.10.100", '00:00:00:00:00:05'),
}

class Part3Controller(object):
  """
  A controller class for managing OpenFlow switches and setting up rules.
  """

  def __init__(self, connection):
    """
    Initializes the controller with a connection to a switch.

    Args:
      connection: The OpenFlow connection to the switch.
    """
    # Print the datapath ID of the connected switch
    print(connection.dpid)
    # Keep track of the connection to the switch
    self.connection = connection
    # Bind the PacketIn event listener to handle incoming packets
    connection.addListeners(self)
    # Determine the switch type based on its datapath ID
    if connection.dpid == 1:
      self.s1_setup()
    elif connection.dpid == 2:
      self.s2_setup()
    elif connection.dpid == 3:
      self.s3_setup()
    elif connection.dpid == 21:
      self.cores21_setup()
    elif connection.dpid == 31:
      self.dcs31_setup()
    else:
      print("UNKNOWN SWITCH")
      exit(1)

  # Setup rules for switch 1 (s1)
  def s1_setup(self):
    """
    Sets up rules for switch 1 (s1).
    | s1,s2,s3,dcs31 | s1 | any | accept |
    | hnotrust | s1 | icmp | drop |
    """
    self._install_accept_hosts_rule(IPS["h10"][0])
    self._install_drop_hnotrust_icmp_rule(IPS["h10"][0])

  # Setup rules for switch 2 (s2)
  def s2_setup(self):
    """
    Sets up rules for switch 2 (s2).
    | s1,s2,s3,dcs31 | s2 | any | accept |
    | hnotrust | s2 | icmp | drop |
    """
    self._install_accept_hosts_rule(IPS["h20"][0])
    self._install_drop_hnotrust_icmp_rule(IPS["h20"][0])

  # Setup rules for switch 3 (s3)
  def s3_setup(self):
    """
    Sets up rules for switch 3 (s3).
    | s1,s2,s3,dcs31 | s3 | any | accept |
    | hnotrust | s3 | icmp | drop |
    """
    self._install_accept_hosts_rule(IPS["h30"][0])
    self._install_drop_hnotrust_icmp_rule(IPS["h30"][0])

  # Setup rules for core switch (cores21)
  def cores21_setup(self):
    """
    Sets up rules for the core switch (cores21).
    | s1 port | cores21 | any | accept? |
    | s2 port | cores21 | any | accept |
    | s3 port | cores21 | any | accept |
    | dcs31 port | cores21 | any | accept |
    """
    accept_action = of.ofp_action_output(port=of.OFPP_IN_PORT) 
    flow_mod = of.ofp_flow_mod()
    flow_mod.actions.append(accept_action)
    self.connection.send(flow_mod)

  # Setup rules for datacenter switch (dcs31)
  def dcs31_setup(self):
    """
    Sets up rules for the datacenter switch (dcs31).
    | s1,s2,s3,dcs31 | dcs31 | any | accept |
    | hnotrust | dcs31/serv1? | icmp | drop |
    | hnotrust | dcs31/serv1? | ip | drop |
    """
    self._install_accept_hosts_rule(IPS["serv1"][0])
    self._install_dcs31_drop_rules()

  # Install a rule to accept traffic from specified destination IP
  def _install_accept_hosts_rule(self, dst_ip):
    """
    Installs a rule to accept traffic from a specified destination IP.

    Args:
      dst_ip: The destination IP address.
    """
    host_match = of.ofp_match()
    host_match.dl_type = IPV4
    host_match.nw_dst = dst_ip  # redundant
    host_accept_action = of.ofp_action_output(port=of.OFPP_FLOOD)
    host_flow_mod = of.ofp_flow_mod()
    host_flow_mod.match = host_match
    host_flow_mod.actions.append(host_accept_action)
    self.connection.send(host_flow_mod)

  # Install a rule to drop ICMP traffic from the untrusted host
  def _install_drop_hnotrust_icmp_rule(self, dst_ip):
    """
    Installs a rule to drop ICMP traffic from the untrusted host to all hosts.

    Args:
      dst_ip: The destination IP address.
    """
    drop_match = of.ofp_match()
    drop_match.dl_type = IPV4
    drop_match.nw_src = IPS["hnotrust"][0]
    drop_match.nw_proto = ICMP_PROTO
    drop_match.nw_dst = dst_ip
    drop_flow_mod = of.ofp_flow_mod()
    drop_flow_mod.match = drop_match
    self.connection.send(drop_flow_mod)

  # Install rules to drop ICMP and IP traffic from the untrusted host to server 1
  def _install_dcs31_drop_rules(self):
    """
    Installs rules to drop ICMP and IP traffic from the untrusted host to server 1.
    """
    drop_match = of.ofp_match()
    drop_match.nw_src = IPS["hnotrust"][0]
    drop_match.nw_dst = IPS["serv1"][0] # redundant 
    drop_flow_mod = of.ofp_flow_mod()
    drop_flow_mod.match = drop_match
    self.connection.send(drop_flow_mod)

  # Handle PacketIn events
  def _handle_PacketIn(self, event):
    """
    Handles PacketIn events triggered when packets are not handled by router rules.

    Args:
      event: The PacketIn event object.
    """
    packet = event.parsed # Parsed packet data
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return
    packet_in = event.ofp # The actual ofp_packet_in message
    print("Unhandled packet from {}: {}".format(self.connection.dpid, packet.dump()))

# Launch the controller
def launch():
  """
  Launches the controller component.
  """
  def start_switch(event):
    log.debug("Controlling %s" % (event.connection,))
    Part3Controller(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
