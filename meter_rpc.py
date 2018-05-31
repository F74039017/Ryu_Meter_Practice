import pyjsonrpc
import json
import sys
from ovsdb_test import RPC_PORT

# Usage: python rpc.py <server ip address>

class ryuRPC:
    def __init__(self):
        # prepare client rpc
        self.httpClient = pyjsonrpc.HttpClient(
            url = 'http://' + sys.argv[1] + ':' + str(RPC_PORT)
        )

        FORMAT_STR = 'Format: <meter_id> <dst_ip> <dst_port> <max_rate>'

        print FORMAT_STR
        while True:
            self.add_qos_rule()

    def add_qos_rule(self):
        instr = {}
        cmd = raw_input('Command> ').split(' ') # wait command

        try:
            if cmd[0] == 'exit' or cmd[0] == 'quit':
                sys.exit(0)

            _cmd = {}
            _cmd['meter_id'] = cmd[0]
            _cmd['dst_ip'] = cmd[1]
            _cmd['dst_port'] = cmd[2]
            _cmd['max_rate'] = cmd[3]

            print self.httpClient.call('add_meter_rule', _cmd) # rpc call
        except IndexError:
            print 'Wrong Command!!'
            print FORMAT_STR


if __name__ == "__main__":
    
    if len(sys.argv)!=2:
        print "Usage: python rpc.py <rpc server ip>"
        sys.exit(1)

    demo = ryuRPC()
