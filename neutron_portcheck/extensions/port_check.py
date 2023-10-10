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

import abc
import os

from neutron_lib.api import extensions as api_extensions
from neutron_lib.api import faults
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
import six

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import resource
from neutron import wsgi


PORT_CHECK = 'port-check'
extensions.append_api_extensions_path([os.path.dirname(__file__)])


class PortCheckController(wsgi.Controller):
    def create(self, request, **kwargs):
        if not request.context.is_admin:
            reason = _("Only admin is authorized to access port check API")
            raise n_exc.AdminRequired(reason=reason)
        port_id = kwargs['port_id']
        plugin = directory.get_plugin(PORT_CHECK)
        return plugin.port_check(request.context, port_id)


class Port_check(api_extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Port-check extenstion"

    @classmethod
    def get_alias(cls):
        return "port-check"

    @classmethod
    def get_description(cls):
        return "Port-check extension"

    @classmethod
    def get_updated(cls):
        return "2022-04-22T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        controller = resource.Resource(PortCheckController(), faults.FAULT_MAP)
        parent = {'member_name': 'port', 'collection_name': 'ports'}
        ext = extensions.ResourceExtension('check', controller, parent)
        return [ext]

    @classmethod
    def get_plugin_interface(cls):
        return PortCheckPluginBase


@six.add_metaclass(abc.ABCMeta)
class PortCheckPluginBase(service_base.ServicePluginBase):

    def get_plugin_type(self):
        return PORT_CHECK

    def get_plugin_description(self):
        return 'Port-check plugin'

    @abc.abstractmethod
    def port_check(self, context, port_id):
        pass
