from swift.common.swob import wsgify
from swift.common.middleware.crypto_service import CryptoService
from swift.proxy.controllers.base import get_container_info


class SEL_Encryption():

    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.cs = CryptoService()

    @wsgify
    def __call__(self, req):
        version, account, container, obj = req.split_path(1, 4, True)
        resp = req.get_response(self.app)
        container_info = get_container_info(req.environ, self.app)
        cont_version = container_info['meta'].get('version')
        # Overencryption
        if req.method == 'GET' and obj is not None:
            obj_version = resp.headers.get('x-object-meta-version')
            if cont_version != obj_version:
                sel_key = self.cs.generate_token()
                resp.body = self.cs.encrypt_object(resp.body, sel_key)
                resp.headers['X-SEL-Key'] = sel_key

        return resp


def filter_factory(global_conf, **local_conf):
    conf = dict(global_conf, **local_conf)
    return lambda app: SEL_Encryption(app, conf)
