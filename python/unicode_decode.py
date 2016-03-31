#coding=utf-8

from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
from burp import IBurpExtenderCallbacks


import re

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Unicode decode")

        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest,messageInfo):
        if toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER or toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER:
            if not messageIsRequest:
                response = messageInfo.getResponse()
                analyzedResponse = self._helpers.analyzeResponse(response)
                headers = analyzedResponse.getHeaders()
                new_headers = []
                for header in headers:
                    if header.startswith("Content-Type:"):
                        new_headers.append(header.replace('iso-8859-1', 'utf-8'))
                    else:
                        new_headers.append(header)

                print new_headers

                body = response[analyzedResponse.getBodyOffset():]
                body_string = body.tostring()
                print body_string
                u_char_escape_list = re.findall(r'(?:\\u[\d\w]{4})+', body_string)
                for u_char_escape in u_char_escape_list:
                    print u_char_escape
                    u_char = u_char_escape.decode('unicode_escape').encode('utf8')
                    body_string = body_string.replace(u_char_escape ,u_char)

                new_body = self._helpers.bytesToString(body_string)

                messageInfo.setResponse(self._helpers.buildHttpMessage(new_headers, new_body))


