Welcome!
========

This package contains the Neutron extenstion for port troubleshooting.
This package requires Neutron to run.

Installation:
===================
1. Enable the Port-check plug-in in the **/etc/neutron/neutron.conf** file by
appending **port_check** to **service_plugins** in **[DEFAULT]**:

.. code-block:: ini

    [DEFAULT]
    # ...
    service_plugins = port_check

2. Configure the Port-check plugin for the L2 agent by adding to
**/etc/neutron/ml2_conf.ini** the following section:

.. code-block:: ini

    [agent]
    # ...
    extensions = port_check


3. Restart the neutron-server in controller node to apply the settings.

4. Restart the neutron-openvswitch-agent in all agent nodes to apply the settings.

5. Install **neutron-portcheck-client** from
https://github.com/antonkurbatov/neutron-portcheck-client


Using Nueton Port-check extenstion:
========================

1. Create some port (via an instance creation or some other way).

.. code-block:: bash

    $ openstack port show d1cfaf7f-149d-4e00-b2f4-bd3562a76738 -c fixed_ips -c mac_address
    +-------------+------------------------------------------------------------------------------+
    | Field       | Value                                                                        |
    +-------------+------------------------------------------------------------------------------+
    | fixed_ips   | ip_address='192.168.1.201', subnet_id='96e9f5ee-8eab-497e-a167-e5a7e581b22d' |
    | mac_address | fa:16:3e:14:b6:10                                                            |
    +-------------+------------------------------------------------------------------------------+
2. Check the port:

.. code-block:: bash

    $ openstack port check d1cfaf7f-149d-4e00-b2f4-bd3562a76738
    +---------------------+-------+
    | Field               | Value |
    +---------------------+-------+
    | bindings            | ok    |
    | openvswitch_agent   | ok    |
    | port_status         | ok    |
    | provisioning_blocks | ok    |
    +---------------------+-------+

3. Corrupt the port flows:

.. code-block:: bash
    
    $ ovs-ofctl dump-flows br-int | grep fa:16:3e:14:b6:10
     cookie=0x9a99edb0bd7bfaed, duration=1506.220s, table=60, n_packets=26, n_bytes=2392, idle_age=6852, priority=90,dl_vlan=3,dl_dst=fa:16:3e:14:b6:10 actions=load:0x1e->NXM_NX_REG5[],load:0x3->NXM_NX_REG6[],strip_vlan,resubmit(,81)
     cookie=0x9a99edb0bd7bfaed, duration=1506.211s, table=71, n_packets=4, n_bytes=168, idle_age=459, priority=95,arp,reg5=0x1e,in_port=30,dl_src=fa:16:3e:14:b6:10,arp_spa=192.168.1.201 actions=resubmit(,94)
     cookie=0x9a99edb0bd7bfaed, duration=1506.208s, table=71, n_packets=0, n_bytes=0, idle_age=1506, priority=65,ip,reg5=0x1e,in_port=30,dl_src=fa:16:3e:14:b6:10,nw_src=192.168.1.201 actions=ct(table=72,zone=NXM_NX_REG6[0..15])
     cookie=0x9a99edb0bd7bfaed, duration=1506.206s, table=71, n_packets=0, n_bytes=0, idle_age=1506, priority=65,ipv6,reg5=0x1e,in_port=30,dl_src=fa:16:3e:14:b6:10,ipv6_src=fe80::f816:3eff:fe14:b610 actions=ct(table=72,zone=NXM_NX_REG6[0..15])
     cookie=0x9a99edb0bd7bfaed, duration=1506.195s, table=73, n_packets=67, n_bytes=7405, idle_age=9660, priority=100,reg6=0x3,dl_dst=fa:16:3e:14:b6:10 actions=load:0x1e->NXM_NX_REG5[],resubmit(,81)
     cookie=0x9a99edb0bd7bfaed, duration=1506.189s, table=94, n_packets=0, n_bytes=0, idle_age=9676, priority=12,reg6=0x3,dl_dst=fa:16:3e:14:b6:10 actions=output:30
    $ ovs-ofctl del-flows br-int table=60,dl_dst=fa:16:3e:14:b6:10
    $ ovs-ofctl del-flows br-int table=71,dl_src=fa:16:3e:14:b6:10,arp_spa=192.168.1.201,arp


4. Check the port again:

.. code-block:: bash
    
    $ openstack port check d1cfaf7f-149d-4e00-b2f4-bd3562a76738
    +---------------------+-------------------------------------------------------------------------------------------------------------------------------------------------+
    | Field               | Value                                                                                                                                           |
    +---------------------+-------------------------------------------------------------------------------------------------------------------------------------------------+
    | bindings            | ok                                                                                                                                              |
    | openvswitch_agent   | - error:                                                                                                                                        |
    |                     |     Flow not found                                                                                                                              |
    |                     |   flow:                                                                                                                                         |
    |                     |     table=60,dl_dst=fa:16:3e:14:b6:10,dl_vlan=3 [priority=90,actions=load:0x1e->NXM_NX_REG5[],load:0x3->NXM_NX_REG6[],strip_vlan,resubmit(,81)] |
    |                     |   frame:                                                                                                                                        |
    |                     |     File "/usr/lib/python2.7/site-packages/neutron/agent/linux/openvswitch_firewall/firewall.py", line 845, in initialize_port_flows            |
    |                     |       ovs_consts.BASE_INGRESS_TABLE),                                                                                                           |
    |                     | - error:                                                                                                                                        |
    |                     |     Flow not found                                                                                                                              |
    |                     |   flow:                                                                                                                                         |
    |                     |     table=71,arp,reg5=0x1e,dl_src=fa:16:3e:14:b6:10,arp_spa=192.168.1.201,in_port=30 [priority=95,actions=resubmit(,94)]                        |
    |                     |   frame:                                                                                                                                        |
    |                     |     File "/usr/lib/python2.7/site-packages/neutron/agent/linux/openvswitch_firewall/firewall.py", line 949, in _initialize_egress               |
    |                     |       ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE)                                                                                          |
    | port_status         | ok                                                                                                                                              |
    | provisioning_blocks | ok                                                                                                                                              |
    +---------------------+-------------------------------------------------------------------------------------------------------------------------------------------------+
