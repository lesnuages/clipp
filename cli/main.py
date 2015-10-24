#! /usr/bin/env python
#coding: utf-8

import os
import glob
import cmd
import subprocess
import pickle
from core.utils                 import SessionFormatter, SearchUtils, format_json
from tabletext                  import to_text
from core.analysis.analyzer     import PcapAnalyzer
from docopt                     import docopt, DocoptExit
#from progress.bar               import Bar

def _append_slash_if_dir(p):
    if p and os.path.isdir(p) and p[-1] != os.sep:
        return p + os.sep
    return p


def docopt_cmd(func):
    """
    Decorator for interactive 
    usage of docopt parsing.
    Catches the DocoptExit and
    SystemExit exceptions raised by
    the docopt function.
    """
    def fn(self, arg):
        try:
            opt = docopt(fn.__doc__, arg)
        except DocoptExit as e:
            print(e)
            return
        except SystemExit:
            return
        return func(self, opt)
    fn.__name__ = func.__name__
    fn.__doc__  = func.__doc__
    fn.__dict__.update(func.__dict__)
    return fn

class Colors:
    RESET_ALL = "\033[0m"
    BOLD      = "\033[1m"

    """
    Foreground colors.
    """
    F_BLACK   = "\033[30m"
    F_RED     = "\033[31m"
    F_GREEN   = "\033[32m"
    F_YELLOW  = "\033[33m"
    F_BLUE    = "\033[34m"
    F_MAGENTA = "\033[35m"
    F_CYAN    = "\033[36m"
    F_WHITE   = "\033[37m"
    F_RESET   = "\033[39m"

    """
    Background colors.
    """
    B_BLACK   = "\033[40m"
    B_RED     = "\033[41m"
    B_GREEN   = "\033[42m"
    B_YELLOW  = "\033[43m"
    B_BLUE    = "\033[44m"
    B_MAGENTA = "\033[45m"
    B_CYAN    = "\033[46m"
    B_WHITE   = "\033[47m"
    B_RESET   = "\033[49m"

class Workspace:

    def __init__(self, name, analyzer):
        self.name = name
        self.serialized_file = None 
        self.analyzer = analyzer

    def create_structure(self):
        if not os.path.exists('~/.config/clipp/'):
            os.mkdir('~/.config/clipp')

    def save(self):
        self.serialized_file = "%s.workspace" % (self.name)
        with open(self.serialized_file, 'wb') as output:
            pickle.dump(self.analyzer.sessions, output)
    
    def load(self):
        with open(self.serialized_file, 'rb') as infile:
            self.analyzer.sessions = pickle.load(infile)

class BaseConsole(cmd.Cmd):

    magic_cmd = {
            'ls':'ls --color=auto',
            'll':'ls -lh --color=auto', 
            'la':'ls -lah --color=auto', 
            'cat':'cat', 
            'grep':'grep --color=auto'
            }

    def __init__(self, *args, **kwargs):
        cmd.Cmd.__init__(self, *args, **kwargs)

    def do_set(self, args):
        splitted = args.split('=')
        param = splitted[0]
        value = True if int(splitted[1]) == 1 else False
        self.config.update({param : value})

    def cmdloop(self, no_intro=False):
        try:
            intro = self.intro if not no_intro else ""
            cmd.Cmd.cmdloop(self, intro=intro)
        except KeyboardInterrupt:
            print("^C")
            self.cmdloop(True)

    def autocomplete_path(self, text, line, begidx, endidx):
        before_arg = line.rfind(" ", 0, begidx)
        if before_arg == -1:
            return
        fixed   = line[before_arg+1:begidx]
        arg     = line[before_arg+1:endidx]
        pattern = arg + '*'

        completions = []
        for path in glob.glob(pattern):
            path = _append_slash_if_dir(path)
            completions.append(path.replace(fixed, "", 1))
        return completions


    def default(self,args):
        first = args.split(' ')[0]
        if first in self.magic_cmd.keys():
            new_line = args.replace(first, self.magic_cmd[first])
            subprocess.call(['zsh', '-c', new_line])
        else:
            self.print_error("No such command. Try 'help' to list available commands.")

    def do_shell(self, args):
        try:
            subprocess.call(['zsh', '-c', args])
        except OSError as e:
            print(e)

    def print_info(self, data):
        print(Colors.BOLD + Colors.F_BLUE + "[*] " + Colors.RESET_ALL + data)

    def print_error(self, data):
        print(Colors.BOLD + Colors.F_RED + "[*] " + Colors.RESET_ALL + data)

    def print_warning(self, data):
        print(Colors.BOLD + Colors.F_YELLOW + "[*] " + Colors.RESET_ALL + data)

    def print_default(self, data):
        print(Colors.BOLD + Colors.F_GREEN + "[*] " + Colors.RESET_ALL + data)

    def complete_shell(self, text, line, begidx, endidx):
        return self.autocomplete_path(text, line, begidx, endidx)

    def emptyline(self):
        pass

    def do_quit(self, args):
        return self.do_exit(args)

    def do_exit(self, args):
        return True

    def do_EOF(self, args):
        return True

class ClippConsole(BaseConsole):

    intro = """
      ________    ___         ___    ________    ________   
     |\   ____\  |\  \       |\  \  |\   __  \  |\   __  \  
     \ \  \___|  \ \  \      \ \  \ \ \  \|\  \ \ \  \|\  \ 
      \ \  \      \ \  \      \ \  \ \ \   ____\ \ \   ____\ 
       \ \  \___ _ \ \  \____  \ \  \ \ \  \___|  \ \  \___|
        \ \_______\ \ \_______\ \ \__\ \ \__\      \ \__\   
         \|_______|  \|_______|  \|__|  \|__|       \|__|       

    Command Line Interface Packet Parser.

    Type "help" or "?" to list available commands.

    Type "help <command>" to see the command's help.
    """

    prompt = Colors.BOLD + Colors.F_BLUE + "clipp>>" + Colors.RESET_ALL

    def __init__(self):
        BaseConsole.__init__(self)
        self.analyzer = PcapAnalyzer()
        self.config = {'mobile': False, 'ip-layer' : False}
        self.current_session = None

    def do_clean(self, args):
        self.analyzer.sessions.clear()
        self.print_info("All sessions have been erased.")
        self.current_session = None
        self.reset_prompt()

    def reset_prompt(self):
        self.prompt = Colors.BOLD + Colors.F_BLUE + "clipp>>" + Colors.RESET_ALL

    @docopt_cmd
    def do_load(self, args):
        """Usage: load <filename>

        Loads pcap file and parse it.
        """
        try:
            self.analyzer.set_filepath(args['<filename>'])
            self.analyzer.parse_file(self.config['mobile'], self.config.get('ip-layer', False))
        except Exception as e:
            print(e)

    @docopt_cmd
    def do_sessions(self, args):
        """Usage: sessions [<session_id>]

        Print session list, or enter session if <session_id> is given.
        """
        if args['<session_id>'] in self.analyzer.sessions.keys():
            self.prompt = Colors.BOLD + Colors.F_BLUE + "clipp[%s]>>" % (args['<session_id>']) + Colors.RESET_ALL
            self.current_session = args['<session_id>']
        else:
            header = ['Session ID', 'IP SRC', 'DOMAIN SRC', 'PORT SRC', 'IP DST', 'DOMAIN DST' ,'PORT DST', 'PROTO', 'PACKETS', 'LENGTH']
            data = []
            for key, session in self.analyzer.sessions.iteritems():
                session_dict = session.serialize()
                data.append([key,
                            session_dict['ip_src'],
                            session_dict['domainsrc'],
                            session_dict['sport'],
                            session_dict['ip_dst'],
                            session_dict['domaindst'],
                            session_dict['dport'],
                            session_dict['proto'],
                            session_dict['pkts'],
                            session_dict['tot_len']])
            if len(data) > 0:
                print(to_text([header] + data))

    def do_info(self, args):
        if self.current_session:
            session = self.analyzer.sessions[self.current_session]
            self.print_default("Session infos :")
            print("Key : \t\t %s" % self.current_session)
            print("NB Packets : \t %d" % session.nb_pkts)
            print("Total length : \t %d" % session.tot_len)
            print("Protocol : \t %s" % session.proto)
            print("IP src : \t %s" % session.ip_src)
            print("IP dst : \t %s" % session.ip_dst)
            print("Port src : \t %d" % session.sport)
            print("Port dst : \t %d" % session.dport)

    def do_show(self, args):
        if self.current_session:
            session = self.analyzer.sessions[self.current_session]
            data = []
            header = ['PKT NUM', 'IP SRC', 'PORT SRC', 'IP DST', 'PORT DST', 'LENGTH']
            for index, pkt in enumerate(session.packets):
                data.append([index,
                             self.analyzer.ip_to_str(pkt.raw_ip.src),
                             pkt.raw_ip.data.sport,
                             self.analyzer.ip_to_str(pkt.raw_ip.dst),
                             pkt.raw_ip.data.dport,
                             len(pkt.data)])
            if len(data) > 0:
                print(to_text([header] + data))

    def do_back(self, args):
        self.current_session = None
        self.reset_prompt()

    @docopt_cmd
    def do_stream(self, args):
        """Usage: 
        stream [-f=<fmt> | --format=<fmt>] [-p=<pkt> | --packet=<pkt>]

        Print session data (TCP/UDP).

        -f <fmt>, --format <fmt>    output format, default is "hex": str, urldecode, hex, hexarray, json, base64 (decode)
        -p <pkt>, --packet <pkt>    only print the packet data instead of session data. Default is -1 (all packets).
        """
        if self.current_session:
            pkt = args['--packet'] if args['--packet'] else -1
            fmt = args['--format'] if args['--format'] else 'hex'
            pkt = int(pkt)
            formatter = SessionFormatter(self.analyzer.sessions[self.current_session])
            results = formatter.format(fmt, pkt)
            self.print_stream(results, pkt) if pkt >= 0 else map(lambda tpl : self.print_stream(tpl[1], tpl[0]), enumerate(results))

    def print_stream(self, stream_data, pkt):
        if len(stream_data) > 0:
            self.print_default("%s[Packet %d]%s" % (Colors.F_CYAN, pkt, Colors.RESET_ALL))
            print(stream_data)


    @docopt_cmd
    def do_dump(self, args):
        """Usage: 
        dump [-p=<pkt> |--packet=<pkt>] <filename>

        Dump session (all packets by default) or packet data to file.

        -p=<pkt>, --packet=<pkt>    packet to dump.
        <filename>                  full path to the output file.
        """
        if self.current_session:
            pkt         = int(args['--packet']) if args['--packet'] else -1
            filename    = args['<filename>']
            session     = self.analyzer.sessions[self.current_session]
            with open(filename, 'wb') as output:
                output.write(session.packets[pkt].data) if pkt >= 0 else map(lambda p : output.write(p.data), session.packets)
        else:
            self.print_error("You must select a session first. Use 'sessions <session_id>' to select a session.")

    @docopt_cmd
    def do_search(self, args):
        """Usage: search [options] (-s|-x) <pattern>...

        -s, --string            the string pattern to find.
        -x, --hexstr            the hex string to find.

        Options:
        -c, --case-sensitive    match case sensitive pattern.
        -S, --sessions-only     only print sessions id where the pattern was found.
        """
        searcher = SearchUtils(self.analyzer.sessions)
        fmt     = 'str' if args['--string'] else 'hex'
        pattern = ' '.join(args['<pattern>']) if fmt == 'str' else ''.join(args['<pattern>'])
        results = searcher.search(pattern, fmt, self.current_session, args['--case-sensitive'])
        self.print_search_results(results, args['--sessions-only'], pattern)

    def print_search_results(self, results, sessions_only, pattern):
        if results:
            if sessions_only:
                [self.print_default(key) for key in results.keys()]
            else:
                for skey, listtuple in results.iteritems():
                    self.print_default("%sSession %s%s" % (Colors.BOLD + Colors.F_MAGENTA, skey, Colors.RESET_ALL))
                    for pindex, indexes, fmt in listtuple:
                        pkt = self.analyzer.sessions[skey].packets[pindex]
                        res_data = self.format_search_results(pattern, pkt, indexes, fmt)
                        self.print_default("{}[Packet {}]:".format(Colors.F_CYAN, pindex, Colors.RESET_ALL))
                        for res in res_data:
                            output = "{}".format(res)
                            self.print_default(output)

    def format_search_results(self, pattern, pkt, indexes, fmt):
        return [self.format_search_result(pattern, pkt, index, fmt) for index in indexes]

    def format_search_result(self, pattern, pkt, index, fmt):
        threshold = 40
        if fmt == 'hex':
            data = pkt.data.encode('hex')
        elif fmt == 'str':
            data = pkt.strings
        original = data[index:index+len(pattern)]
        start = index - threshold if index > threshold else 0
        end = index + threshold if len(data) - index > threshold else len(data)
        prefix = '[...]' if start > 0 else ''
        suffix = '[...]' if end < len(data) else ''
        return prefix + data[start:index] + Colors.BOLD + Colors.F_RED + original + Colors.RESET_ALL + data[index+len(pattern):end] + suffix
    
    @docopt_cmd
    def do_http(self, args):
        """Usage: http [options]

        Options:
        --headers   only print http headers.
        --body      only print http body.
        """
        if self.current_session:
            session = self.analyzer.sessions[self.current_session]
            for index, pkt in enumerate(session.packets):
                if pkt.http:
                    self.print_default("{}[Packet %d]{}".format(Colors.F_CYAN, index, Colors.RESET_ALL))
                    if args['--headers']:
                        self.print_default(str(pkt.http.headers))
                    elif args['--body']:
                        self.print_default(str(pkt.http.body))
                    else:
                        self.print_default(str(pkt.http.headers))
                        self.print_default(str(pkt.http.body))
    
    @docopt_cmd
    def do_extract(self, args):
        """Usage: extract [options] (-p=<pkt>|--packet=<pkt>) 

        -p=<pkt>, --packet=<pkt>    packet number (mandatory).
        -u, --unquote               urldecode the data.
        """
        if self.current_session:
            formatter = SessionFormatter(self.analyzer.sessions[self.current_session])
            pkt = int(args['--packet'])
            if args['--unquote']:
                kv_data = formatter.unquote_pkt(pkt).split('&')
            else:
                kv_data = formatter.strings_pkt(pkt).split('&')
            for kv in kv_data:
                try:
                    params = kv.split('=')
                    self.print_default('Key   : %s' % params[0])
                    json_data = format_json(params[1])
                    self.print_default('Value : ')
                    print json_data
                except Exception:
                    self.print_default('Value : %s' % params[1])
            

    def complete_load(self, text, args, begidx, endidx):
        return self.autocomplete_path(text, args, begidx, endidx)

    def complete_sessions(self, text, args, begidx, endidx):
        return self.autocomplete_session_key(text)

    def complete_stream(self, text, args, begidx, endidx):
        params = ['-f', '-p', '--format', '--packet', 'str', 'json', 'urldecode', 'base64', 'hex', 'hexarray']
        return filter(lambda s: s.startswith(text), params)

    def autocomplete_session_key(self, text):
        return filter(lambda s: s.startswith(text), self.analyzer.sessions.keys())

if __name__ == '__main__':
    ClippConsole().cmdloop()
