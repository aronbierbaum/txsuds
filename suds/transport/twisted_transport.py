import logging
import os

log = logging.getLogger(__name__)

import twisted.internet
from twisted.internet          import defer, reactor
from twisted.internet.protocol import ClientFactory, Protocol
from twisted.internet.ssl      import CertificateOptions
from twisted.web.client        import Agent, WebClientContextFactory, _parse
from twisted.web.http_headers  import Headers
from twisted.web.iweb          import IBodyProducer
from twisted.web._newclient    import HTTP11ClientProtocol, Request
from OpenSSL                   import crypto

from zope.interface            import implements

from suds.transport import Reply, Transport


class StringResponseConsumer(Protocol):
    """
    Protocol that consumes the entire response body into a string and provides
    a simple callback interface for the user to be triggered when the response
    is complete.

    @ivar response:  The response that filled us.
    @ivar _finished: Deferred that is triggered when the body is completed.
    """
    def __init__(self):
        self._finished = defer.Deferred()
        self.response  = None
        self.body      = ""

    def getDeferred(self):
        """ Return the deferred that is triggered after full completion. """
        return self._finished

    def dataReceived(self, data):
        self.body = self.body + data

    def connectionLost(self, reason):
        """ Callback to finished with copy of ourselves. """
        self._finished.callback(self)

    def responseWithoutBody(self):
        """ Called when the response does not contain a body. """
        self._finished.callback(self)


class StringProducer(object):
    """
    Simple wrapper around a string that will produce that string with the correct
    interface.
    """
    implements(IBodyProducer)

    def __init__(self, body):
        self.body   = body
        self.length = len(body)

    def startProducing(self, consumer):
        consumer.write(self.body)

        return defer.succeed(None)


class ContextFactory(CertificateOptions, WebClientContextFactory):
    """
    Custom context facotry that allows any hostname and port combination.
    """
    def __init__(self, **kwargs):
        CertificateOptions.__init__(self, **kwargs)

    def getContext(self, hostname, port):
        return CertificateOptions.getContext(self)


class _HTTP11ClientFactory(ClientFactory):
    """
    A simple factory for L{HTTP11ClientProtocol}, used by L{ProxyAgent}.

    @since: 11.1
    """
    protocol = HTTP11ClientProtocol


class ProxyAgent(Agent):
    """
    An HTTP agent able to cross HTTP proxies.

    @ivar _factory: The factory used to connect to the proxy.

    @ivar _proxyEndpoint: The endpoint used to connect to the proxy, passing
        the factory.

    @since: 11.1
    """

    _factory = _HTTP11ClientFactory

    def __init__(self, endpoint):
        self._proxyEndpoint = endpoint

    def _connect(self, scheme, host, port):
        """
        Ignore the connection to the expected host, and connect to the proxy
        instead.
        """
        return self._proxyEndpoint.connect(self._factory())

    def request(self, method, uri, headers=None, bodyProducer=None):
        """
        Issue a new request via the configured proxy.
        """
        scheme, host, port, path = _parse(uri)
        request_path = uri

        d = self._connect(scheme, host, port)

        if headers is None:
            headers = Headers()
        if not headers.hasHeader('host'):
            # This is a lot of copying.  It might be nice if there were a bit
            # less.
            headers = Headers(dict(headers.getAllRawHeaders()))
            headers.addRawHeader(
                'host', self._computeHostValue(scheme, host, port))
        def cbConnected(proto):
            # NOTE: For the proxy case the path should be the full URI.
            return proto.request(Request(method, request_path, headers, bodyProducer))
        d.addCallback(cbConnected)
        return d




class TwistedTransport(Transport):
    """
    Custom transport that uses the Twisted REST client.
    """
    def __init__(self):
        """
        Constructor.
        """
        Transport.__init__(self)
        from suds.transport.options import Options
        self.options = Options()
        del Options
        self._contextFactory = None

    def _getContextFactory(self):
        """
        Helper method that lazily constructs the context factory for this
        transport.
        """
        if self._contextFactory is not None:
            return self._contextFactory

        # Attempt to load the certificate and private key from a file.
        certificate = None
        if self.options.certificate:
            cert_data = self.options.certificate
            if os.path.isfile(cert_data):
                with open(cert_data, "rb") as cert_file:
                    cert_data = cert_file.read()
            certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
        priv_key = None
        if self.options.privateKey:
            key_data = self.options.privateKey
            if os.path.isfile(key_data):
                with open(key_data, "rb") as key_file:
                    key_data = key_file.read()
            priv_key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_data)

        # Get the rest of the options for the context factory.
        other_opts = {}
        for opt_name in ['method', 'verify', 'caCerts', 'verifyDepth',
                         'requireCertificate', 'verifyOnce', 'enableSingleUseKeys',
                         'enableSessions', 'fixBrokenPeers', 'enableSessionTickets']:
            other_opts[opt_name] = getattr(self.options, opt_name)


        self._contextFactory = ContextFactory(privateKey = priv_key,
                                              certificate = certificate,
                                              **other_opts)
        return self._contextFactory
    contextFactory = property(_getContextFactory)

    @defer.inlineCallbacks
    def _request(self, request, method):
        """
        Helper method that sends the given HTTP request.
        """
        # Copy the headers from the request.
        headers = Headers()
        for (key, value) in request.headers.iteritems():
            headers.addRawHeader(key, value)

        # If a username and password are given, then add basic authentication.
        if (self.options.username is not None and
            self.options.password is not None):
            auth = "%s:%s" % (self.options.username, self.options.password)
            auth = auth.encode("base64").strip()
            headers.addRawHeader('Authorization', 'Basic ' + auth)

        # Construct an agent to send the request.
        producer = StringProducer(request.message or "")
        agent = Agent(reactor, self.contextFactory)
        #from twisted.internet.endpoints import TCP4ClientEndpoint
        #endpoint = TCP4ClientEndpoint(reactor, "localhost", 8080)
        #agent = ProxyAgent(endpoint)

        url = request.url.encode("utf-8")
        response = yield agent.request(method, url, headers, producer)

        # Construct a simple response consumer and give it the response body.
        consumer = StringResponseConsumer()
        response.deliverBody(consumer)
        yield consumer.getDeferred()
        consumer.response = response
        defer.returnValue(consumer)

    @defer.inlineCallbacks
    def open(self, request):
        """
        Open the url in the specified request.

        @param request: A transport request.
        @type  request: L{Request}

        @return: An input stream.
        @rtype:  stream

        @raise TransportError: On all transport errors.
        """
        if request.url.startswith("file:///"):
            local_fname = os.path.normpath(request.url[8:])
            with open(local_fname, "rb") as local_file:
                content = local_file.read()
            defer.returnValue(content)

        consumer = yield self._request(request, "GET")
        defer.returnValue(consumer.body)

    @defer.inlineCallbacks
    def send(self, request):
        """
        Send soap message.  Implementations are expected to handle:
            - proxies
            - I{http} headers
            - cookies
            - sending message
            - brokering exceptions into L{TransportError}

        @param request: A transport request.
        @type request: L{Request}
        @return: The reply
        @rtype: L{Reply}
        @raise TransportError: On all transport errors.
        """
        consumer = yield self._request(request, "POST")
        res_headers = dict(consumer.response.headers.getAllRawHeaders())
        result = Reply(consumer.response.code, res_headers, consumer.body)
        defer.returnValue(result)
