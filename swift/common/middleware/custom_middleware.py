from swift.common.utils import get_logger


LOG_NAME = 'proxy-server'


class OverencSwift(object):

    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(conf, log_route=LOG_NAME)

    def __call__(self, req):
        if req.method == 'GET':
            self.logger.info('Executing a GET request')
        response = req.get_response(self.app)
        return response


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def get_enc_swift(app):
        return OverencSwift(app, conf)

    return get_enc_swift
