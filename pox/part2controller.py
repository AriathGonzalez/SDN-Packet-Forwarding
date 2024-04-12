from pox.core import core
import pox.openflow.libopenflow_01 as of

# Define constants for protocol and ether types
IPV4 = 0x0800
ICMP_PROTO = 1  # ICMP protocol number
ARP_ETHERTYPE = 0X0806  # ARP ether type

log = core.getLogger()


class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.

  | src ip   | dst ip   | protocol | action |
  |----------|----------|----------|--------|
  | any ipv4 | any ipv4 | icmp     | accept |
  | any      | any      | arp      | accept |
  | any ipv4 | any ipv4 | ---      | drop   |
  """
  def __init__(self, connection):
    """
     Initializes the firewall for a switch connection.

     Args:
         connection: The OpenFlow connection to the switch.
    """
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Add switch rules here
    self._install_icmp_rule()
    self._install_arp_rule()
    self._install_drop_rule()

  def _install_icmp_rule(self):
    """
     Installs a rule to accept ICMP traffic.
     | any ipv4 | any ipv4 | icmp | accept |
    """
    # Create an OpenFlow match object
    icmp_match = of.ofp_match()
    icmp_match.dl_type = IPV4  # Setting Ether type / length
    icmp_match.nw_proto = ICMP_PROTO  # Setting IP protocol
    # Create an OpenFlow action to accept the icmp traffic
    icmp_accept_action = of.ofp_action_output(port=of.OFPP_FLOOD)
    # Create an OpenFlow flow_mod message to install the rule
    icmp_flow_mod = of.ofp_flow_mod()
    icmp_flow_mod.match = icmp_match
    icmp_flow_mod.actions.append(icmp_accept_action)
    # Install the icmp_flow_mod message to the switch
    self.connection.send(icmp_flow_mod)

  def _install_arp_rule(self):
    """
     Installs a rule to accept ARP traffic.
     | any | any | arp | accept |
    """
    arp_match = of.ofp_match()
    arp_match.dl_type = ARP_ETHERTYPE
    arp_accept_action = of.ofp_action_output(port=of.OFPP_FLOOD) 
    arp_flow_mod = of.ofp_flow_mod()
    arp_flow_mod.match = arp_match
    arp_flow_mod.actions.append(arp_accept_action)
    # Install the arp_flow_mod message to the switch
    self.connection.send(arp_flow_mod)

  def _install_drop_rule(self):
    """
     Installs a default rule to drop all other IPv4 traffic.
     | any ipv4 | any ipv4 | --- | drop |
    """
    drop_match = of.ofp_match()
    drop_match.dl_type = IPV4
    drop_flow_mod = of.ofp_flow_mod()
    drop_flow_mod.match = drop_match
    # Install the drop_flow_mod message to the switch
    self.connection.send(drop_flow_mod)

  def _handle_PacketIn(self, event):
    """
    Packets not handled by the router rules will be
    forwarded to this method to be handled by the controller

    Args:
            event: The PacketIn event triggered by the switch.
    """

    packet = event.parsed  # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp  # The actual ofp_packet_in message.
    print("Unhandled packet :" + str(packet.dump()))


def launch():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
