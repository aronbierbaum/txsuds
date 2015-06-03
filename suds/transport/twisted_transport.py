import os
import urllib
import urlparse

from twisted.internet            import defer, reactor
from twisted.internet.endpoints  import TCP4ClientEndpoint
from twisted.internet.protocol   import Protocol
from twisted.web.client          import Agent, ProxyAgent, _requireSSL
from twisted.web.http_headers    import Headers
from twisted.web.iweb            import IBodyProducer, IPolicyForHTTPS
from OpenSSL                     import crypto
from zope.interface              import implements, implementer

from suds.transport           import Reply, Transport
from suds.transport.sslverify import optionsForClientTLS


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

    def pauseProducing(self):
        pass

    def resumeProducing(self):
        pass

    def stopProducing(self):
        pass


@implementer(IPolicyForHTTPS)
class PolicyForHTTPS(object):
    """
    Custom SSL connection creator that allows specifying private key, certificate
    and custom options.
    """
    def __init__(self, trustRoot = None, privateKey = None, certificate = None, **kwargs):
        self._trustRoot = trustRoot
        self._opts = dict(kwargs)
        self._opts["privateKey"] = privateKey
        self._opts["certificate"] = certificate

    @_requireSSL
    def creatorForNetloc(self, hostname, port):
        """
        Create a client connection creator for a given network location.

        @param hostname: The hostname part of the URI.
        @type  hostname: L{bytes}
        @param port:     The port part of the URI.
        @type  port:     L{int}
        """
        return optionsForClientTLS(hostname.decode("ascii"),
                                   trustRoot = self._trustRoot,
                                   extraCertificateOptions = self._opts)


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
        self._httpsPolicy = None

    def _getHttpsPolicy(self):
        """
        Helper method that lazily constructs the HTTPS options to use for this
        transport.
        """
        if self._httpsPolicy is not None:
            return self._httpsPolicy

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
        for opt_name in ['method', 'verify', 'caCerts', 'verifyDepth', 'trustRoot',
                         'requireCertificate', 'verifyOnce', 'enableSingleUseKeys',
                         'enableSessions', 'fixBrokenPeers', 'enableSessionTickets',
                         'acceptableCiphers']:
            other_opts[opt_name] = getattr(self.options, opt_name)


        self._httpsPolicy = PolicyForHTTPS(privateKey = priv_key,
                                           certificate = certificate,
                                           **other_opts)
        return self._httpsPolicy
    httpsPolicy = property(_getHttpsPolicy)

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

        # Determine if the user has configured a proxy server.
        url_parts = urlparse.urlparse(request.url)
        proxy = self.options.proxy.get(url_parts.scheme, None)

        # Construct an agent to send the request.
        if proxy is not None:
            (hostname, port) = proxy.split(":")
            endpoint = TCP4ClientEndpoint(reactor, hostname, int(port),
                                          timeout = self.options.timeout)
            agent = ProxyAgent(endpoint)
        else:
            agent = Agent(reactor, self.httpsPolicy,
                          connectTimeout = self.options.timeout)

        url = request.url.encode("utf-8")
        producer = StringProducer(request.message or "")
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
        if request.url.startswith("file://"):
            url_parts   = urlparse.urlparse(request.url)
            full_path   = os.path.join(url_parts.netloc, url_parts.path)
            local_fname = urllib.url2pathname(full_path)

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
