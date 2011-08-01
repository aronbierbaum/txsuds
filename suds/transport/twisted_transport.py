import logging

log = logging.getLogger(__name__)

import twisted.internet
from twisted.internet          import defer, reactor
from twisted.internet.protocol import Protocol
from twisted.web.client        import Agent
from twisted.web.http_headers  import Headers
from twisted.web.iweb          import IBodyProducer
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
   # pylint: disable-msg=W0222
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
        headers = Headers()
        for (key, value) in request.headers.iteritems():
            headers.addRawHeader(key, value)

        if (self.options.username is not None and
            self.options.password is not None):
            auth = "%s:%s" % (self.options.username, self.options.password)
            auth = auth.encode("base64").strip()
            headers.addRawHeader('Authorization', 'Basic ' + auth)

        producer = StringProducer(request.message or "")
        agent = Agent(reactor)
        url = request.url.encode("utf-8")
        response = yield agent.request("GET", url, headers, producer)
        consumer = StringResponseConsumer()
        response.deliverBody(consumer)
        yield consumer.getDeferred()
        res_headers = dict(response.headers.getAllRawHeaders())
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
        headers = Headers()
        for (key, value) in request.headers.iteritems():
            headers.addRawHeader(key, value)

        if (self.options.username is not None and
            self.options.password is not None):
            auth = "%s:%s" % (self.options.username, self.options.password)
            auth = auth.encode("base64").strip()
            headers.addRawHeader('Authorization', 'Basic ' + auth)

        producer = StringProducer(request.message or "")
        agent = Agent(reactor)
        response = yield agent.request("POST", request.url, headers, producer)
        consumer = StringResponseConsumer()
        response.deliverBody(consumer)
        yield consumer.getDeferred()
        res_headers = dict(response.headers.getAllRawHeaders())
        result = Reply(response.code, res_headers, consumer.body)
        defer.returnValue(result)
