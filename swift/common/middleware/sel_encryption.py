from swift.common.swob import wsgify
from swift.common.middleware.crypto_service import CryptoService
from swift.proxy.controllers.base import get_container_info
from swift.common.request_helpers import get_sys_meta_prefix

META_OE = 'oe-version'
SYSMETA_OBJ_OE = get_sys_meta_prefix('object') + META_OE
SYSMETA_CONTAINER_OE = get_sys_meta_prefix('container') + META_OE


class SEL_Encryption():

    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.cs = CryptoService()

    @wsgify
    def __call__(self, req):
        version, account, container, obj = req.split_path(1, 4, True)

        if container is not None:
            container_info = get_container_info(req.environ, self.app)

        # PUT container
        if container and not obj and req.method == 'PUT':
            req.headers[SYSMETA_CONTAINER_OE] = '0'

        # PUT object
        if obj and req.method == 'PUT':
            req.headers[SYSMETA_OBJ_OE] = container_info['sysmeta'].get(META_OE, '0')

        # pass request to next wsgi middleware and get response
        resp = req.get_response(self.app)

        # HEAD/GET container
        if container and not obj and req.method in ('HEAD', 'GET'):
            resp.headers['X-' + META_OE] = resp.headers.get(SYSMETA_CONTAINER_OE, '')

        # HEAD object
        if obj and req.method == 'HEAD':
            resp.headers['X-' + META_OE] = resp.headers.get(SYSMETA_OBJ_OE, '')

        # GET object (OverEncryption)
        if req.method == 'GET' and obj is not None:
            cont_version = container_info['sysmeta'].get(META_OE, '')
            obj_version = resp.headers.get(SYSMETA_OBJ_OE, '')
            resp.headers['X-' + META_OE] = resp.headers.get(SYSMETA_OBJ_OE, '')
            if cont_version != obj_version:
                sel_key = self.cs.generate_token()
                resp.body = self.cs.encrypt_object(resp.body, sel_key)
                resp.headers['X-SEL-Key'] = sel_key

        return resp


def filter_factory(global_conf, **local_conf):
    conf = dict(global_conf, **local_conf)
    return lambda app: SEL_Encryption(app, conf)
