from cStringIO import StringIO
from swift.common.swob import wsgify
from swift.common.http import is_success
from swift.common.overencryption_utils import generate_random_key, encrypt_object, revoking_users
from swift.proxy.controllers.base import get_container_info
from swift.common.request_helpers import get_sys_meta_prefix

META_OE = 'oe-version'
SYS_OBJ = get_sys_meta_prefix('object') + META_OE
SYS_CONT = get_sys_meta_prefix('container') + META_OE


class SEL_Encryption():

    def __init__(self, app, conf):
        self.app = app
        self.conf = conf

    @wsgify
    def __call__(self, req):
        version, account, container, obj = req.split_path(1, 4, True)

        if obj:
            container_info = get_container_info(req.environ, self.app)

        # PUT container
        if container and not obj and req.method == 'PUT':
            req.headers[SYS_CONT] = '0'

        # POST container
        if container and not obj and req.method == 'POST':
            cont_version = container_info['sysmeta'].get(META_OE, '')
            revoked_users = revoking_users(container_info, req.headers)
            if cont_version.isdigit() and revoked_users:
                req.headers[SYS_CONT] = int(cont_version) + 1

        # PUT object
        if obj and req.method == 'PUT':
            req.headers[SYS_OBJ] = container_info['sysmeta'].get(META_OE, '0')

        # pass request to next wsgi middleware and get response
        resp = req.get_response(self.app)

        # HEAD/GET container
        if container and not obj and req.method in ('HEAD', 'GET'):
            resp.headers['X-' + META_OE] = resp.headers.get(SYS_CONT, '')

        # HEAD object
        if obj and req.method == 'HEAD':
            resp.headers['X-' + META_OE] = resp.headers.get(SYS_OBJ, '')

        # GET object (OverEncryption)
        if req.method == 'GET' and obj:
            cont_version = container_info['sysmeta'].get(META_OE, '')
            obj_version = resp.headers.get(SYS_OBJ, '')
            resp.headers['X-' + META_OE] = resp.headers.get(SYS_OBJ, '')
            if cont_version != obj_version:
                sel_key = generate_random_key()
                resp.body = encrypt_object(resp.body, sel_key)
                resp.headers['X-SEL-Key'] = sel_key.encode('base64')

                # do the materialization
                if 'X-SEL-Materialize' in req.headers:
                    data = 'OVERWRITTEN' # debug
                    destination = resp.environ['PATH_INFO']

                    new_env = req.environ.copy()
                    new_env['REQUEST_METHOD'] = 'PUT'
                    new_env['PATH_INFO'] = destination
                    new_env['wsgi.input'] = StringIO(data) # it has readline
                    new_env['CONTENT_LENGTH'] = len(data)
                    new_env['swift.source'] = 'SEL'
                    new_env['HTTP_USER_AGENT'] = \
                        '%s SelEncryption' % req.environ.get('HTTP_USER_AGENT')

                    put_obj_req = Request.blank(destination, new_env)
                    put_obj_resp = put_obj_req.get_response(self.app)

                    # for debug purposes, return the PUT response if not success
                    if not is_success(put_obj_resp.status_int):
                        return put_obj_resp

        return resp


def filter_factory(global_conf, **local_conf):
    conf = dict(global_conf, **local_conf)
    return lambda app: SEL_Encryption(app, conf)
