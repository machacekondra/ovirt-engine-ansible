# -*- coding: utf-8 -*-

#
# Copyright (c) 2016 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import io
import json
import os
import pycurl
import six
import sys
import threading

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode


class Request(object):
    """
    This class represents an HTTP request.

    This class is intended for internal use by other components of the SDK.
    Refrain from using it directly as there is no backwards compatibility
    guarantee.
    """

    def __init__(
        self,
        method='GET',
        path='',
        query=None,
        headers=None,
        body=None,
    ):
        self.method = method
        self.path = path
        self.query = query if query is not None else {}
        self.headers = headers if headers is not None else {}
        self.body = body


class Response(object):
    """
    This class represents an HTTP response.

    This class is intended for internal use by other components of the SDK.
    Refrain from using it directly as there is no backwards compatibility
    guarantee.
    """

    def __init__(
        self,
        body=None,
        code=None,
        headers=None,
        message=None
    ):
        self.body = body
        self.code = code
        self.headers = headers if headers is not None else {}
        self.message = message


class Error(Exception):
    """
    General exception which is thrown by SDK,
    indicates that some exception happened in SDK.
    """
    pass


class Connection(object):
    """
    This class is responsible for managing an HTTP connection to the engine
    server. It is intended as the entry point for the SDK, and it provides
    access to the `system` service and, from there, to the rest of the
    services provided by the API.
    """

    def __init__(
        self,
        url=None,
        username=None,
        password=None,
        insecure=False,
        ca_file=None,
        kerberos=False,
        timeout=0,
        compress=False,
        sso_url=None,
        sso_revoke_url=None,
        sso_token_name='access_token',
        sso_token=None,
    ):
        """
        Creates a new connection to the API server.

        This method supports the following parameters:

        `url`:: A string containing the base URL of the server, usually
        something like `https://server.example.com/ovirt-engine/api`.

        `username`:: The name of the user, something like `admin@internal`.

        `password`:: The name password of the user.

        `insecure`:: A boolean flag that indicates if the server TLS
        certificate and host name should be checked.

        `ca_file`:: A PEM file containing the trusted CA certificates. The
        certificate presented by the server will be verified using these CA
        certificates. If `ca_file` parameter is not set, system wide
        CA certificate store is used.

        `kerberos`:: A boolean flag indicating if Kerberos
        authentication should be used instead of the default basic
        authentication.

        `timeout`:: The maximum total time to wait for the response, in
        seconds. A value of zero (the default) means wait for ever. If
        the timeout expires before the response is received an exception
        will be raised.

        `compress`:: A boolean flag indicating if the SDK should ask
        the server to send compressed responses. The default is `False`.
        Note that this is a hint for the server, and that it may return
        uncompressed data even when this parameter is set to `True`.

        `sso_url`:: A string containing the base SSO URL of the serve.
        Default SSO url is computed from the `url` if no `sso_url` is provided.

        `sso_revoke_url`:: A string containing the base URL of the SSO
        revoke service. This needs to be specified only when using
        an external authentication service. By default this URL
        is automatically calculated from the value of the `url` parameter,
        so that SSO token revoke will be performed using the SSO service
        that is part of the engine.

        `sso_token_name`:: The token name in the JSON SSO response returned
        from the SSO server. Default value is `access_token`.

        `sso_token`:: The SSO token to be used. If specified, new SSO token
        won't be created.
        """

        # Check mandatory parameters:
        if url is None:
            raise Error('The \'url\' parameter is mandatory')

        # Check that the CA file exists:
        if ca_file is not None and not os.path.exists(ca_file):
            raise Error('The CA file \'%s\' doesn\'t exist' % ca_file)

        # Save the URL:
        self._url = url

        # Save the credentials:
        self._username = username
        self._password = password
        self._kerberos = kerberos

        # The curl object can be used by several threads, but not
        # simultaneously, so we need a lock to prevent that:
        self._curl_lock = threading.Lock()

        # Set SSO attributes:
        self._sso_url = sso_url
        self._sso_revoke_url = sso_revoke_url
        self._sso_token_name = sso_token_name
        self._sso_token = sso_token

        # Create the curl handle that manages the pool of connections:
        self._curl = pycurl.Curl()
        self._curl.setopt(pycurl.COOKIEFILE, '/dev/null')
        self._curl.setopt(pycurl.COOKIEJAR, '/dev/null')

        # Configure TLS parameters:
        if url.startswith('https'):
            self._curl.setopt(pycurl.SSL_VERIFYPEER, 0 if insecure else 1)
            self._curl.setopt(pycurl.SSL_VERIFYHOST, 0 if insecure else 2)
            if ca_file is not None:
                self._curl.setopt(pycurl.CAINFO, ca_file)

        # Configure timeouts:
        self._curl.setopt(pycurl.TIMEOUT, timeout)

        # Configure compression of responses (setting the value to a zero
        # length string means accepting all the compression types that
        # libcurl supports):
        if compress:
            self._curl.setopt(pycurl.ENCODING, '')

    def send(self, request):
        """
        Sends an HTTP request and waits for the response.

        This method is intended for internal use by other components of the
        SDK. Refrain from using it directly, as backwards compatibility isn't
        guaranteed.

        This method supports the following parameters.

        `request`:: The Request object containing the details of the HTTP
        request to send.

        The returned value is a Request object containing the details of the
        HTTP response received.
        """

        with self._curl_lock:
            try:
                return self.__send(request)
            except pycurl.error as e:
                six.reraise(
                    Error,
                    Error("Error while sending HTTP request", e),
                    sys.exc_info()[2]
                )

    def __send(self, request):
        # Create SSO token if needed:
        if self._sso_token is None:
            self._sso_token = self._get_access_token()

        # Set the method:
        self._curl.setopt(pycurl.CUSTOMREQUEST, request.method)

        # Build the URL:
        url = self._build_url(
            path=request.path,
            query=request.query,
        )
        self._curl.setopt(pycurl.URL, url)

        # Basic credentials should be sent only if there isn't a session:
        if self._kerberos:
            self._curl.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_GSSNEGOTIATE)
            self._curl.setopt(pycurl.USERPWD, ':')
        else:
            authorization = '%s:%s' % (self._username, self._password)
            self._curl.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_BASIC)
            self._curl.setopt(pycurl.USERPWD, authorization)

        # Add headers, avoiding those that have no value:
        header_lines = []
        for header_name, header_value in request.headers.items():
            if header_value is not None:
                header_lines.append('%s: %s' % (header_name, header_value))
        header_lines.append('User-Agent: oVirtAnsibleModule')
        header_lines.append('Version: 4')
        header_lines.append('Content-Type: application/json')
        header_lines.append('Accept: application/json')
        header_lines.append('Authorization: Bearer %s' % self._sso_token)

        # Make sure headers values are strings, because
        # pycurl version 7.19.0 supports only string in headers
        for i, header in enumerate(header_lines):
            try:
                header_lines[i] = header.encode('ascii')
            except UnicodeDecodeError:
                header_name, header_value = header.split(':')
                raise Error(
                    "The value '{header_value}' of header '{header_name}' "
                    "contains characters that can't be encoded using ASCII, "
                    "as required by the HTTP protocol.".format(
                        header_value=header_value,
                        header_name=header_name,
                    )
                )

        # Copy headers and the request body to the curl object:
        self._curl.setopt(pycurl.HTTPHEADER, header_lines)
        body = request.body
        if body is None:
            body = ''
        self._curl.setopt(pycurl.POSTFIELDS, body)

        # Prepare the buffers to receive the response:
        body_buf = io.BytesIO()
        headers_buf = io.BytesIO()
        self._curl.setopt(pycurl.WRITEFUNCTION, body_buf.write)
        self._curl.setopt(pycurl.HEADERFUNCTION, headers_buf.write)

        # Send the request and wait for the response:
        self._curl.perform()

        # Extract the response code and body:
        response = Response()
        response.code = self._curl.getinfo(pycurl.HTTP_CODE)
        response.body = json.loads(body_buf.getvalue())

        # The response code can be extracted directly, but cURL doesn't
        # have a method to extract the response message, so we have to
        # parse the first header line to find it:
        response.reason = ""
        headers_text = headers_buf.getvalue().decode('ascii')
        header_lines = headers_text.split('\n')
        if len(header_lines) >= 1:
            response_line = header_lines[0]
            response_fields = response_line.split()
            if len(response_fields) >= 3:
                response.reason = ' '.join(response_fields[2:])

        # Return the response:
        return response

    @property
    def url(self):
        """
        Returns a string containing the base URL used by this connection.
        """

        return self._url

    def _revoke_access_token(self):
        """
        Revokes access token
        """

        # Build the SSO revoke URL:
        if self._sso_revoke_url is None:
            self._sso_revoke_url = (
                '{url}/services/sso-logout?{query}'
            ).format(
                url=self._url[:self._url.rindex('/')],
                query=urlencode({
                    'scope': 'ovirt-app-api',
                    'token': self._sso_token,
                })
            )

        sso_response = self._get_sso_response(self._sso_revoke_url)

        if isinstance(sso_response, list):
            sso_response = sso_response[0]

        if 'error' in sso_response:
            raise Error(
                'Error during SSO revoke %s : %s' % (
                    sso_response['error_code'],
                    sso_response['error']
                )
            )

    def _get_access_token(self):
        """
        Creates access token which reflect authentication method.
        """

        # Build SSO URL:
        if self._kerberos:
            entry_point = 'token-http-auth'
            grant_type = 'urn:ovirt:params:oauth:grant-type:http'
        else:
            entry_point = 'token'
            grant_type = 'password'

        if self._sso_url is None:
            self._sso_url = (
                '{url}/sso/oauth/{entry_point}?{query}'
            ).format(
                url=self._url[:self._url.rindex('/')],
                entry_point=entry_point,
                query=urlencode({
                    'grant_type': grant_type,
                    'scope': 'ovirt-app-api',
                })
            )
            if not self._kerberos:
                self._sso_url += '&' + urlencode({
                    'username': self._username,
                    'password': self._password,
                })

        # Set proper Authorization header if using kerberos:
        if self._kerberos:
            self._curl.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_GSSNEGOTIATE)
            self._curl.setopt(pycurl.USERPWD, ':')

        # Send SSO request:
        sso_response = self._get_sso_response(self._sso_url)

        if isinstance(sso_response, list):
            sso_response = sso_response[0]

        if 'error' in sso_response:
            raise Error(
                'Error during SSO authentication %s : %s' % (
                    sso_response['error_code'],
                    sso_response['error']
                )
            )

        return sso_response[self._sso_token_name]

    def _get_sso_response(self, url):
        """
        Perform SSO request and return response body data.
        """

        # Set HTTP method and URL:
        self._curl.setopt(pycurl.CUSTOMREQUEST, 'GET')
        self._curl.setopt(pycurl.URL, url)

        # Prepare headers:
        header_lines = [
            'User-Agent: oVirtAnsibleModule',
            'Accept: application/json'
        ]
        self._curl.setopt(pycurl.HTTPHEADER, header_lines)
        self._curl.setopt(pycurl.POSTFIELDS, '')

        # Prepare the buffer to receive the response:
        body_buf = io.BytesIO()
        self._curl.setopt(pycurl.WRITEFUNCTION, body_buf.write)

        # Send the request and wait for the response:
        self._curl.perform()
        return json.loads(body_buf.getvalue().decode('utf-8'))

    def close(self):
        """
        Releases the resources used by this connection.
        """

        # Revoke access token:
        self._revoke_access_token()

        # Release resources used by the cURL handle:
        with self._curl_lock:
            self._curl.close()

    def _build_url(self, path='', query=None):
        """
        Builds a request URL from a path, and the set of query parameters.

        This method is intended for internal use by other components of the
        SDK. Refrain from using it directly, as backwards compatibility isn't
        guaranteed.

        This method supports the following parameters:

        `path`:: The path that will be added to the base URL. The default is an
        empty string.

        `query`:: A dictionary containing the query parameters to add to the
        URL. The keys of the dictionary should be strings containing the names
        of the parameters, and the values should be strings containing the
        values.

        The returned value is an string containing the URL.
        """
        if path.startswith('/ovirt-engine/api'):
            path = path[17:]

        # Add the path and the parameters:
        url = '%s%s' % (self._url, path)
        if query:
            url = '%s?%s' % (url, urlencode(query))
        return url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
