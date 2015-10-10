#coding: utf-8

import json
import StringIO
from pygments               import highlight
from pygments.lexers.data   import JsonLexer
from pygments.formatters    import TerminalFormatter
from requests.utils         import unquote

def format_json(data):
    obj = json.loads(data)
    output = StringIO.StringIO()
    json.dump(obj, output, sort_keys=True, indent=2)
    return highlight(output.getvalue(), JsonLexer(), TerminalFormatter())

class SessionFormatter:

    def __init__(self, session):
        self.session = session

    def format(self, fmt='hex', index=-1):
        actions = {'str':self.strings_pkt,
                   'hex':self.hex_pkt,
                   'urldecode':self.unquote_pkt,
                   'base64': self.b64decode_pkt,
                   'json': self.pjson_strings,
                   'hexarray': self.hex_array}
        if fmt in actions.keys():
            return actions[fmt](index) if index >= 0 else [actions[fmt](x) for x in range(self.session.nb_pkts)]
        return []

    def hex_pkt(self, pkt_index):
        return self.session.packets[pkt_index].data.encode('hex')

    def strings_pkt(self, index):
        return self.session.packets[index].strings

    def unquote_pkt(self, index):
        return unquote(self.strings_pkt(index))

    def b64decode_pkt(self, index):
        return self.strings_pkt(index).decode('base64')

    def pjson_strings(self, index):
        result = ""
        try:
            data = self.unquote_pkt(index).split('\r\n\r\n')[1]
            result = format_json(data)
        except Exception as e:
            print(e)
        finally:
            return result

    def hex_array(self, index):
        return self.hexdump(self.session.packets[index].data)

    def hexdump(self, src, length=16):
        result = []
        digits = 4 if isinstance(src, unicode) else 2
        for i in xrange(0, len(src), length):
            s = src[i:i+length]
            hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
            text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
            result.append(b"%04X: %-*s %s" % (i, length*(digits + 1), hexa, text))
        return b'\n'.join(result)

class SearchUtils:

    def __init__(self, sessions):
        self.sessions = sessions

    def get_data(self, pkt, fmt, case_sensitive):
        if case_sensitive:
            if fmt == 'hex':
                return pkt.data.encode('hex')
            elif fmt == 'str':
                return pkt.strings
        else:
            if fmt == 'hex':
                return pkt.data.encode('hex').lower()
            elif fmt == 'str':
                return pkt.strings.lower()

    def find_in_pkt(self, data, pattern, start, end):
        index = start
        results = []
        while index > -1 and index < end:
            index = data.find(pattern, index, end)
            if index > -1:
                results.append(index)
                index += len(pattern)
        return results

    def find_in_pkts(self, packets, pattern, fmt, case_sensitive=False):
        if not case_sensitive:
            pattern = pattern.lower()
        for pindex, pkt in enumerate(packets):
            data = self.get_data(pkt, fmt, case_sensitive)
            indexes = self.find_in_pkt(data, pattern, 0, len(data))
            if len(indexes) > 0:
                yield (pindex, indexes, fmt)

    def search_session(self, pattern, session, fmt='str', case_sensitive=False):
        s = self.sessions[session]
        return list(self.find_in_pkts(s.packets, pattern, fmt, case_sensitive))

    def search(self, pattern, fmt='hex', session=None, case_sensitive=False):
        if session:
            res = self.search_session(pattern, session, fmt, case_sensitive)
            if len(res) > 0:
                return {session : res}
        else:
            result = {}
            for skey, sobj in self.sessions.iteritems():
                res = (self.search_session(pattern, skey, fmt, case_sensitive))
                if len(res) > 0:
                    result[skey] = res
            if len(result.values()) > 0:
                return result
