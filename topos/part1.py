#!/usr/bin/python

"""
Script Description:
This script defines a simple Mininet topology for Part 1 of a network configuration.
The topology consists of one switch and four hosts connected as follows:
[h1] --- {s1} --- [h2]
[h3] -- /    \ -- [h4]

[x] = host x
{y} = switch y
--- = link between node and switch

Usage:
To use this script, simply run it using Python.
This will create the defined network topology and start the Mininet CLI for interaction.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.cli import CLI


class part1_topo(Topo):

    def build(self):
        """"
           Method Description:
           Builds the network topology for Part 1, connecting four hosts to one switch.
        """

        # Add Switches
        s1 = self.addSwitch('s1')

        # Add Hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        # Add Links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)


topos = {'part1' : part1_topo}


def configure():
    """
       Method Description:
       Configures the Mininet environment for the defined network topology.
       Starts the Mininet network and CLI for interaction.
    """

    t = part1_topo()
    net = Mininet(topo=t)
    net.start()
    CLI(net)
    net.stop()


if __name__ == '__main__':
    configure()
