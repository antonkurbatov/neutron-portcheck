import functools

from oslo_log import log as logging

from neutron_portcheck import exceptions


LOG = logging.getLogger(__name__)


def safe_func(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except exceptions.PortCheckError as err:
            return [{'error': str(err)}]
        except Exception as err:
            LOG.exception('Unexpected error')
            return [{'error': str(err)}]
    return wrapper
