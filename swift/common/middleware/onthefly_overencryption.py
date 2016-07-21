# Unibg Seclab

"""
Middleware that will provide on-the-fly OverEncryption support.
It filters the requests arriving from the users and provides an
Encryption Layer to protect data from access revocation.

This middleware just builds a proof of concept: the SEL keys are not
protected (encrypted with the user's public key).

--------------------------
put_container
--------------------------

Everytime a new container is put, it gets a 'version' header set to 0.
This means that the container is encrypted, but it is still at its
first version, i.e. no user has ever been revocated from the ACL.

--------------------------
put_object
--------------------------
The object gets a metadatum 'version' equal to the container version.
This permits to create a 'history of puts', and let users know what
key to use to decrypt the content.

--------------------------
post_container
--------------------------
When a users wants to edit the metadata of a container, the middleware
controls if the ACL has been changed, and in case a user has been
revocated, it updates the container version

--------------------------
get_object
--------------------------
This is the trickiest call. If the object version is equal to the contaner
version, the object is sent to the user 'as is'.
In case the version of the object is different from the container version,
it means that it is not protected against access revocation.
So, before sending the object to the user, the middleware generates a SEL
key and encrypts the object. Then it stores the key in the headers of the
response.
"""

from swift.common.swob import wsgify
from swift.common.overencryption_utils import generate_random_key, encrypt_object, revoking_users
from swift.proxy.controllers.base import get_container_info
from swift.common.request_helpers import get_sys_meta_prefix

META_OE = 'oe-version'
SYS_OBJ = get_sys_meta_prefix('object') + META_OE
SYS_CONT = get_sys_meta_prefix('container') + META_OE

META_KEY = 'SEL-Key'
SYS_KEY = get_sys_meta_prefix('object') + META_KEY


class OnTheFlySEL():

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
            container_info = get_container_info(req.environ, self.app)
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

            if cont_version == obj_version:  # SEL not needed, add oe header
                resp.headers['X-' + META_OE] = obj_version

            else:  # SEL needed
                sel_key = generate_random_key()
                resp.app_iter = encrypt_object(resp.app_iter, sel_key)
                resp.headers['X-SEL-Key'] = sel_key

        return resp


def filter_factory(global_conf, **local_conf):
    conf = dict(global_conf, **local_conf)
    return lambda app: OnTheFlySEL(app, conf)
