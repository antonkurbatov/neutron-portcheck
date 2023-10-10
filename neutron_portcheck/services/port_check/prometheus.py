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

from threading import Lock
from wsgiref import simple_server

from oslo_log import log as logging
import prometheus_client

LOG = logging.getLogger(__name__)
REGISTRY = prometheus_client.CollectorRegistry(auto_describe=True)
metrics_lock = Lock()


class PortStatusMetric(prometheus_client.Gauge):
    def clear(self):
        with self._lock:
            self._metrics = {}


port_status_metric = PortStatusMetric(
    'neutron_port_status_failed',
    'Neutron port status fail metrics',
    labelnames=('port_id', 'check', 'device_id', 'device_owner'),
    registry=REGISTRY
)


def start_prometheus_client(port):
    try:
        LOG.info("Starting prometheus server on port %s", port)
        app = prometheus_client.make_wsgi_app(registry=REGISTRY)

        def process_reuqest(environ, start_response):
            with metrics_lock:
                return app(environ, start_response)

        httpd = simple_server.make_server('', port, process_reuqest)
        httpd.serve_forever()
    finally:
        LOG.info("Stopping prometheus server")
        httpd.server_close()
