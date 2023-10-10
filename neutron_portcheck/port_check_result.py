# Copyright 2023 Acronis
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

import collections

CHECKS = frozenset((
    'status',
    'binding',
    'provisioning',
    # OVS agent checks:
    'openvswitch_agent',
    'firewall',
    # DHCP agent checks:
    'dhcp',
    # L3 agent checks:
))


class Reports(list):
    def add(self, msg, *args):
        if args:
            msg = msg % args
        self.append(msg)


class PortCheckResult(object):
    def __init__(self):
        self._dict = collections.defaultdict(Reports)

    def to_dict(self):
        return dict(self._dict)

    def __str__(self):
        return '%s(%s)' % (self.__class__.__name__, self.to_dict())

    def update(self, params):
        for key, items in params.items():
            if key not in CHECKS:
                raise ValueError('Unexpected check name: %s' % key)
            self._dict[key].extend(items)

    def __getitem__(self, item):
        if item not in CHECKS:
            raise KeyError(item)
        return self._dict[item]
