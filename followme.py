#!/usr/bin/env python3
from datetime import datetime, timezone
import logging
import socket
#from socket import SOL_TCP
#import sys

PROTO_HEADER = "+RESP:GTFRI,C30203"
sock = socket.socket()

class FollowMeClient:
    def __init__(self, host="165.227.244.196", port=5001, timeout=60):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.connect()

    def connect(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = socket.socket()
        try:
            self.sock.connect((self.host, self.port))
            self.sock.settimeout(self.timeout)
            logging.info(f"FollowMe connected {self.host}:{self.port}")
        except Exception as e:
            logging.error(f"FollowMe connect failed: {e}")
            self.sock = None


    def send(self, imei="666000000000000", name="BeastTest1", hdop=0, speed=0.0, heading=0,
                         alt=0.0, lat=23.971662, lon=120.941, batt=0, loc_time=None):
        if self.sock is None:
            self.connect()
        if self.sock is None:
            return
        if loc_time is None:
            loc_time = datetime.now(timezone.utc)
        if (len(name) > 20):
            logging.error("Invalid format - name: %s", name)
        else:
            name = name.strip().replace(" ", "")
        if (hdop > 50 or hdop < 0):
            logging.error("Invalid format - hdop: %d", hdop)

        if (speed > 999.9 or speed < 0):
            logging.error("Invalid format - speed: %f", speed)
        
        if name == "SouthMelbourne4850":
            imei = "666000000000050"
        elif name == "EYBdd61":
            imei = "666000000000026"
        elif name == "BeastGO":
            imei = "666000000000027"
        elif name == "Beast Solar":
            imei = "666000000000028"
        elif imei == "666000000000000" and name[-2:].isdigit():
            imei = "6660000000000" + name[-2:]
        

        follow_args = [PROTO_HEADER, imei, name, 0, 0, 1, hdop, speed, heading,
                       alt, f"{lon:.6f}", f"{lat:.6f}", loc_time.strftime("%Y%m%d%H%M%S"), '', '' ,
                       '', '', 0.0, batt, datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"), "00E3$"]
        tosend = ""
        for i in follow_args:
            tosend += str(i) + ','
        tosend = tosend[:-1]

        logging.info("[FOLLOWME] %s" % tosend)
        try:
            self.sock.sendall(bytes(tosend, encoding='ascii'))
            logging.info("[FOLLOWME] Sent %s" % name)
        except (BrokenPipeError, OSError) as e:
            logging.error(f"[FOLLOWME] Send failed: {e}, reconnecting...")
            self.connect()
            if self.sock:
                try:
                    self.sock.sendall(bytes(tosend, encoding='ascii'))
                    logging.info("[FOLLOWME] Sent %s (after reconnect)" % name)
                except Exception as e:
                    logging.error(f"[FOLLOWME] Send failed after reconnect: {e}")

"""
def _connect(host, port, timeout=60):
    try:
        sock.connect((host, port))
        sock.settimeout(timeout)
    except socket.error:
        if sock:
            sock.close()
    logging.info("Connected.")


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    #_connect("127.0.0.1", 6999)
    _connect("165.227.244.196", 5001)
    send_to_followme()

if __name__ == "__main__":
    sys.exit(main())
"""
