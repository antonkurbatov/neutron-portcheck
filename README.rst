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
**/etc/neutron/plugins/ml2/ml2_conf.ini** the following section:

.. code-block:: ini

    [agent]
    # ...
    extensions = port_check

3. Apply patches/0001-Make-ConjIdMap-a-real-singleton-object.patch on neutron code

4. Restart the neutron-server in controller node to apply the settings.

5. Restart the neutron-openvswitch-agent in all agent nodes to apply the settings.

6. Install **neutron-portcheck-client** from
https://github.com/antonkurbatov/neutron-portcheck-client


Using Neutron Port-check extenstion:
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
    +--------------+-------+
    | Field        | Value |
    +--------------+-------+
    | binding      | ok    |
    | firewall     | ok    |
    | provisioning | ok    |
    | status       | ok    |
    +--------------+-------+

3. Corrupt the port flows:

.. code-block:: bash
    
    $ ovs-ofctl dump-flows br-int | grep fa:16:3e:14:b6:10
     cookie=0x9a99edb0bd7bfaed, duration=1506.220s, table=60, n_packets=26, n_bytes=2392, idle_age=6852, priority=90,dl_vlan=3,dl_dst=fa:16:3e:14:b6:10 actions=load:0x1e->NXM_NX_REG5[],load:0x3->NXM_NX_REG6[],strip_vlan,resubmit(,81)
     cookie=0x9a99edb0bd7bfaed, duration=1506.211s, table=71, n_packets=4, n_bytes=168, idle_age=459, priority=95,arp,reg5=0x1e,in_port=30,dl_src=fa:16:3e:14:b6:10,arp_spa=192.168.1.201 actions=resubmit(,94)
     ...
    $ ovs-ofctl del-flows br-int table=60,dl_dst=fa:16:3e:14:b6:10
    $ ovs-ofctl del-flows br-int table=71,dl_src=fa:16:3e:14:b6:10,arp_spa=192.168.1.201,arp


4. Check the port again:

.. code-block:: bash
    
    $ openstack port check d1cfaf7f-149d-4e00-b2f4-bd3562a76738
    +--------------+----------------------------------------------------------------------------------------------------------------------------------------------+
    | Field        | Value                                                                                                                                        |
    +--------------+----------------------------------------------------------------------------------------------------------------------------------------------+
    | binding      | ok                                                                                                                                           |
    | firewall     | - No flow: table=60, priority=90,eth_dst=fa:16:3e:14:b6:10,vlan_vid=4099 actions=set_field:30->reg5,set_field:3->reg6,pop_vlan,resubmit(,81) |
    |              | - No flow: table=71, priority=95,in_port=30,arp_spa=192.168.1.201,reg5=30,eth_src=fa:16:3e:14:b6:10,eth_type=2054 actions=resubmit(,94)      |
    | provisioning | ok                                                                                                                                           |
    | status       | ok                                                                                                                                           |
    +--------------+----------------------------------------------------------------------------------------------------------------------------------------------+
