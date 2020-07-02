from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.utils import url_path_join

from traitlets import Dict, Unicode, Bool

import time

import tornado.httputil
from tornado import web

from lxml import etree

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser



class SAMLLoginHandler(BaseHandler):
    def get(self):
        req = self.authenticator.prepare_tornado_request(self.request)
        auth = self.authenticator.init_saml_auth(req)
        return self.redirect(auth.login())

    async def post(self):
        user = await self.login_user()
        if user is None:
            raise web.HTTPError(403)
        self.redirect(self.get_next_url(user))

# class SAMLLogoutHandler(BaseHandler):
#     def get(self):
#         req = self.authenticator.prepare_tornado_request(self.request)
#         auth = self.authenticator.init_saml_auth(req)
#         return_to = url_path_join("http://localhost:8000", "logout/")
#         return self.redirect(auth.logout(return_to=return_to))

#     async def post(self):
#         user = await self.login_user()
#         req = self.authenticator.prepare_tornado_request(self.request)
#         auth = self.authenticator.init_saml_auth(req)
        
#         url = auth.process_slo()
#         errors = auth.get_errors()
#         if len(errors) == 0:
#             if url is not None:
#                 return self.redirect(url)
#             else:
#                 print("Sucessfully Logged out")
#         # if user is None:
#         #     raise web.HTTPError(403)
#         # self.redirect(self.get_next_url(user))

class SAMLMetadataHandler(BaseHandler):
    def get(self):
        req = self.authenticator.prepare_tornado_request(self.request)
        auth = self.authenticator.init_saml_auth(req)
        saml_settings = auth.get_settings()
        metadata = saml_settings.get_sp_metadata()
        errors = saml_settings.validate_metadata(metadata)

        if len(errors) == 0:
            # resp = HttpResponse(content=metadata, content_type='text/xml')
            self.set_header('Content-Type', 'text/xml')
            self.write(metadata)
        else:
            # resp = HttpResponseServerError(content=', '.join(errors))
            self.write(', '.join(errors))


class SAMLAuthenticator(Authenticator):
    """SAML Authenticator"""

    login_handler = SAMLLoginHandler
    # logout_handler = SAMLLogoutHandler
    metadata_handler = SAMLMetadataHandler

    # enable_auth_state = True

    login_service = Unicode(u"SAML",
        help="""
        The name of the SAML based authentication service.
        """,
        config=True
    )

    saml_settings = Dict(
        help="""
        This is a nested dictionary of settings for the python3-saml toolkit.
        """,
        config=True
    )

    saml_namespace = Dict(
        default_value={ 
            'ds'   : 'http://www.w3.org/2000/09/xmldsig#', 
            'md'   : 'urn:oasis:names:tc:SAML:2.0:metadata', 
            'saml' : 'urn:oasis:names:tc:SAML:2.0:assertion', 
            'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol' 
            } ,
        help="""
        The namespace for the SAML xml.
        """,
        config=True
    )

    xpath_username_location = Unicode(
        default_value='//saml:NameID/text()',
        config=True,
        help="""
        This is the xpath to the username location. The namespace is that given
        in saml_namespace.
        """
    )

    auto_IdP_metadata = Unicode(
        default_value=None,
        allow_none=True,
        help="""
        The url to download the IdP metadata. If None, then assume it is manually supplied.
        """,
        config=True
    )

    metadata_url = Unicode(
        default_value=r'/Shiboleth.sso/Metadata',
        help=
        """
        The sub-url where the IdP will look for the metadata.
        """,
        config=True
    )

    # single_log_out = Bool(
    #     default_value=False,
    #     allow_none=False,
    #     help="""
    #     Whether or not to use the single logout service.
    #     """,
    #     config=True
    # )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.auto_IdP_metadata:
            idp_data = OneLogin_Saml2_IdPMetadataParser.parse_remote(self.auto_IdP_metadata)
            self.saml_settings = OneLogin_Saml2_IdPMetadataParser.merge_settings(self.saml_settings, idp_data)


    def login_url(self, base_url):
        return url_path_join(base_url, 'saml_login')

    # def logout_url(self, base_url):
    #     return url_path_join(base_url, 'saml_logout')

    def prepare_tornado_request(self, request):

        dataDict = {}
        for key in request.arguments:
            dataDict[key] = request.arguments[key][0].decode('utf-8')

        result = {
            'https': 'on' if request == 'https' else 'off',
            'http_host': tornado.httputil.split_host_and_port(request.host)[0],
            'script_name': request.path,
            'server_port': tornado.httputil.split_host_and_port(request.host)[1],
            'get_data': dataDict,
            'post_data': dataDict,
            'query_string': request.query
        }
        return result

    def init_saml_auth(self, req):
        auth = OneLogin_Saml2_Auth(req, self.saml_settings)
        return auth

    async def authenticate(self, handler, data):
        req = self.prepare_tornado_request(handler.request)
        auth = self.init_saml_auth(req)

        auth.process_response()
        if not auth.is_authenticated():
            self.log.warning("Unauthorized login attempt.")
            return None

        response_xml = auth.get_last_response_xml()
        tree = etree.fromstring(response_xml)

        username = tree.xpath(self.xpath_username_location, namespaces=self.saml_namespace)[0]
        if not username:
            return None

        app = self.parent
        username = self.normalize_username(username)
        try:
            user = app.users[username]
        except KeyError:
            # first-time login, user not defined yet
            user = None 
            auth_state = None
        else:
            auth_state = await user.get_auth_state()

        userdict = {"name": username}
        message_id = auth.get_last_message_id()

        if isinstance(auth_state, dict):
            message_history = auth_state.get("saml_auth_state", {}).get('saml_message_history', {})

            if message_id in message_history:
                self.log.warning("Replay attack on user %r. Stop authentication.", username)
                return None

            userdict["auth_state"] = auth_state

        else:
            userdict["auth_state"] = auth_state = {}

        saml_auth_state = auth_state.setdefault("saml_auth_state", {})
        saml_message_history = saml_auth_state.setdefault('saml_message_history', {})
        saml_message_history[message_id] = auth.get_last_assertion_not_on_or_after()

        saml_auth_state["saml_message_history"] = self.remove_expired_message_ids(saml_message_history)

        saml_auth_state["attributes"] = auth.get_attributes()
        saml_auth_state["xml"] = response_xml

        return userdict
        

    def remove_expired_message_ids(self, message_history):
        now = time.time()
        keys = [k for k, v in message_history.items() if v < now]
        for k in keys:
            message_history.pop(k)
        return message_history

    def get_handlers(self, app):
        return [
            (r'/saml_login', self.login_handler),
            # (r'/saml_logout', self.logout_handler),
            (self.metadata_url, self.metadata_handler)
        ]