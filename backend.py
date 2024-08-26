#!/usr/bin/env python3
import argparse
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from decimal import Decimal
from flask import Flask
from google.protobuf.json_format import MessageToDict
import logging
from math import sin, cos, sqrt, atan2, radians
import os
import paho.mqtt.client as mqtt
import pickle
from pubsub import pub
import schedule
import signal
import sys
import time

from maprequesthandler2 import MapRequestHandler
from mapnode import MapNode

import meshtastic
import meshtastic.ble_interface
import meshtastic.serial_interface
import meshtastic.tcp_interface
from meshtastic.protobuf import mesh_pb2, mqtt_pb2, portnums_pb2, telemetry_pb2

parser = argparse.ArgumentParser(
                    prog='meshtastic-map-backend',
                    description='Connect to Meshtastic and get node location data',
                    epilog='https://github.com/fifieldt/meshtastic-map-backend')
parser.add_argument('-p', '--port', help='Serial device on which to connect to meshtastic eg /dev/ttyACM0')
parser.add_argument('-b', '--ble', action='store_true', help='Use BLE to connect to a meshtastic device')
parser.add_argument('--latitude', default=25.0122, help='Latitude for centre of map')
parser.add_argument('--longitude', default=121.468, help='Longitude for centre of map')
parser.add_argument('--zoom', default=13, help='Initial map zoom setting')
parser.add_argument('--max-distance', default=100, help='Ignore nodes outside this distance (km), 0 for infinite')
parser.add_argument('--geojson', default="http://127.0.0.1:8100", help='URL to geojson source')
parser.add_argument('--exclusive', help='Only show nodes in the provided file')
parser.add_argument('--mqtt-host', default="mqtt.meshtastic.org", help='Hostname of MQTT Server')
parser.add_argument('--mqtt-port', default=1883, help='Port of MQTT Server')
parser.add_argument('--mqtt-user', default="meshdev", help='MQTT account username')
parser.add_argument('--mqtt-pass', default="large4cats", help='Password of MQTT account')
parser.add_argument('--mqtt-topic', default="msh/TW/#", help='Topic to subscribe to MQTT')
parser.add_argument('--mqtt-clientid', default="mesthastic-map-backend", help='MQTT client ID')
parser.add_argument('--map-reports-only', default=True, help='Only use MQTT map reports to preserve privacy')
parser.add_argument('--lastmessage', default=False, help='Store and share last messages from nodes')

cliargs, _ = parser.parse_known_args()
nodes = {}
mynodes = []

if "RAILWAY_PUBLIC_DOMAIN" in os.environ.keys():
    cliargs.geojson = "https://" + os.environ["RAILWAY_PUBLIC_DOMAIN"]
mrh = MapRequestHandler(cliargs, nodes, mynodes)
app = mrh.getApp()

def cleanExit(sig, frame):
    global nodes
    logging.info('Exiting')
    # don't write the db if it's empty
    if len(nodes) == 0:
        sys.exit(0)

    with open('nodes.db', 'wb') as file:
        pickle.dump(nodes, file)
    sys.exit(0)

def cleanData(threshold=172800):
    # remove old nodes, neighbours, and positions
    for node in list(nodes):
        if (datetime.fromtimestamp(nodes[node].getLastUpdated(style="no") + threshold) < datetime.now()):
            del nodes[node]
        else:
            nodes[node].clean()

def decryptMessage(mp, key="1PG7OiApB1nwvP+rz05pAQ=="):
    """Decrypt a meshtastic message."""

    try:
        # Convert key to bytes
        key_bytes = base64.b64decode(key.encode('ascii'))

        nonce_packet_id = getattr(mp, "id").to_bytes(8, "little")
        nonce_from_node = getattr(mp, "from").to_bytes(8, "little")

        # Put both parts into a single byte array.
        nonce = nonce_packet_id + nonce_from_node

        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_bytes = decryptor.update(getattr(mp, "encrypted")) + decryptor.finalize()

        data = mesh_pb2.Data()
        data.ParseFromString(decrypted_bytes)
        mp.decoded.CopyFrom(data)

    except Exception as e:
        logging.debug(f"failed to decrypt: \n{mp}")
        logging.debug(f"*** Decryption failed: {str(e)}")


def geoItoFloat(geoI):
    return float(geoI * Decimal("1e-7"))


def processPosition(pktfrom, data, max_precision=16):

    # check for validity
    if "latitudeI" not in data.keys() or "longitudeI" not in data.keys():
        logging.warning("Position with no coordinates  %s" % data)
        return

    if cliargs.max_distance != 0:
        latdelta = radians(geoItoFloat(data["latitudeI"])) - radians(float(cliargs.latitude))
        londelta = radians(geoItoFloat(data["longitudeI"])) - radians(float(cliargs.longitude))
        a = sin(latdelta / 2)**2 + cos(radians(float(cliargs.latitude))) * cos(radians(geoItoFloat(data["latitudeI"]))) * sin(londelta / 2)**2
        if 6373.0 * (2 * atan2(sqrt(a), sqrt(1 - a))) > cliargs.max_distance:
            logging.debug("Coordinate Check Failed latcheck=%f, longcheck=%f, %s" %(latdelta, londelta, data))
            return

    if pktfrom not in nodes.keys():
        nodes[pktfrom] = MapNode(pktfrom)

    if "positionPrecision" in data.keys() and data["positionPrecision"] < max_precision:
        precision = data["positionPrecision"]
    else:
        precision = max_precision

    if precision == 0:
        # user requested location not to be sent, but somehow we recieved it.
        return

    if "satsInView" in data.keys() and "altitude" in data.keys():
        logging.info("[POSITION ] %s @ %d, %d %dm 📡%d" %(nodes[pktfrom].getName(),
                                                         data["latitudeI"],
                                                         data["longitudeI"],
                                                         data["altitude"],
                                                         data["satsInView"]))
        nodes[pktfrom].setPosition(geoItoFloat(data["latitudeI"]), geoItoFloat(data["longitudeI"]), precision, data["altitude"])
    elif "altitude" in data.keys():
        logging.info("[POSITION ] %s @ %d, %d %dm" %(nodes[pktfrom].getName(),
                                                    data["latitudeI"],
                                                    data["longitudeI"],
                                                    data["altitude"]))
        nodes[pktfrom].setPosition(geoItoFloat(data["latitudeI"]), geoItoFloat(data["longitudeI"]), precision, data["altitude"])
    else:
        logging.info("[POSITION ] %s @ %d, %d" %(nodes[pktfrom].getName(),
                                                data["latitudeI"],
                                                data["longitudeI"]))

        nodes[pktfrom].setPosition(geoItoFloat(data["latitudeI"]), geoItoFloat(data["longitudeI"]), precision)


def processTelemetry(pktfrom, data):
    if pktfrom not in nodes.keys():
        nodes[pktfrom] = MapNode(pktfrom)

    if "deviceMetrics" in data.keys() and "batteryLevel" in data["deviceMetrics"].keys():
        logging.info("[TELEMETRY] %s 🔋%d%%" % (nodes[pktfrom].getName(),
                                                data["deviceMetrics"]["batteryLevel"]))
        nodes[pktfrom].setMetrics(batterylevel = data["deviceMetrics"]["batteryLevel"])
    elif "deviceMetrics" in data.keys() and len(data["deviceMetrics"].keys()) <= 3:
        # standard channel utilization telemetry - ignore.
        pass
    elif "longName" in data.keys() and "shortName" in data.keys():
        processNodeInfo(pktfrom, data)
    elif "environmentMetrics" in data.keys():
       # we skip environmental metrics (temperature, relative_humidity, barometric_pressure)
       pass
    else:
        logging.warning("???[TELEMETRY] %s %s" % (pktfrom, data))


def processNodeInfo(pktfrom, data):
    if pktfrom not in nodes.keys():
        nodes[pktfrom] = MapNode(pktfrom, data["shortName"], data["longName"])
        logging.info("Added Node %s" % data["longName"])
    else:
        nodes[pktfrom].setName(name = data["shortName"], longname = data["longName"])
    logging.info("[NODEINFO ] %s" % nodes[pktfrom].getName())


def processNeighbourInfo(pktfrom, data):
    if data["nodeId"] not in nodes.keys():
        nodes[data["nodeId"]] = MapNode(pktfrom)
    if "neighbors" not in data.keys():
        # No Neighbours
        data["neighbors"] = []
    for neighbour in data["neighbors"]:
        if neighbour["nodeId"] not in nodes.keys():
            nodes[neighbour["nodeId"]] = MapNode(neighbour["nodeId"])
        if "snr" not in neighbour.keys():
            logging.info("??[NEIGHBOR ] %s" % data)
        nodes[data["nodeId"]].addNeighbour(neighbour["nodeId"], neighbour["snr"])
    logging.info("[NEIGHBOR ] %s" % nodes[pktfrom].getName())


def processTextMessage(pktfrom, pktto, data):
    if cliargs.lastmessage:
        if pktfrom not in nodes.keys():
            nodes[pktfrom] = MapNode(pktfrom)
        nodes[pktfrom].setLastmessage(data)
    logging.info("[TEXT] %d→%d %s" % (pktfrom, pktto, data))

def onReceiveMQTT(client, data, msg):
    se = mqtt_pb2.ServiceEnvelope()
    is_encrypted = False

    try:
        se.ParseFromString(msg.payload)
        mp = se.packet
    except Exception as e:
        logging.debug(f"Received `{msg.payload}` from `{msg.topic}` topic")
        return

    if mp.HasField("encrypted") and not mp.HasField("decoded"):
        decryptMessage(mp)
        is_encrypted=True


    mpdict = MessageToDict(mp)

    try:
        if mp.decoded.portnum == portnums_pb2.MAP_REPORT_APP:
            mr = mqtt_pb2.MapReport()
            mr.ParseFromString(mp.decoded.payload)
            mpdict["decoded"]["mapreport"] = MessageToDict(mr)

        elif mp.decoded.portnum == portnums_pb2.TEXT_MESSAGE_APP:
            mpdict["decoded"]["text"] = mp.decoded.payload.decode("utf-8")

        elif mp.decoded.portnum == portnums_pb2.NODEINFO_APP:
            info = mesh_pb2.User()
            info.ParseFromString(mp.decoded.payload)
            mpdict["decoded"]["user"] = MessageToDict(info)

        elif mp.decoded.portnum == portnums_pb2.POSITION_APP:
            pos = mesh_pb2.Position()
            pos.ParseFromString(mp.decoded.payload)
            mpdict["decoded"]["position"] = MessageToDict(pos)

        elif mp.decoded.portnum == portnums_pb2.TELEMETRY_APP:
            env = telemetry_pb2.Telemetry()
            env.ParseFromString(mp.decoded.payload)
            mpdict["decoded"]["telemetry"] = MessageToDict(env)

        elif mp.decoded.portnum == portnums_pb2.NEIGHBORINFO_APP:
            ni = mesh_pb2.NeighborInfo()
            ni.ParseFromString(mp.decoded.payload)
            mpdict["decoded"]["neighborinfo"] = MessageToDict(ni)


    except Exception as e:
        logging.debug(f"*** Failed to process MQTT Packet {str(e)}")

    onReceive(mpdict, None)


def onReceive(packet, interface):  # pylint: disable=unused-argument
    """called when a packet arrives"""

    if "decoded" not in packet.keys() or "portnum" not in packet["decoded"].keys():
            print(f"???Received: {packet}")
            return

    portnum = packet["decoded"]["portnum"]

    if portnum == "MAP_REPORT_APP":
        logging.info("MAPREPORT:")
        processNodeInfo(packet["from"], packet["decoded"]["mapreport"])
        processPosition(packet["from"], packet["decoded"]["mapreport"])

    elif cliargs.map_reports_only is True:
        # we're looking at the entire world, rather than a private or
        # regional community mesh. Let's not get all of the other data.
        return

    elif portnum == "POSITION_APP":
        try:
            processPosition(packet["from"], packet["decoded"]["position"])
        except KeyError as e:
            logging.debug(f"*** Failed to process MQTT Packet {str(e)}")

    elif portnum == "TELEMETRY_APP":
        try:
            processTelemetry(packet["from"], packet["decoded"]["telemetry"])
        except KeyError as e:
            logging.debug(f"*** Failed to process MQTT Packet {str(e)}")

    elif portnum == "NODEINFO_APP":
        processTelemetry(packet["from"], packet["decoded"]["user"])

    elif portnum == "NEIGHBORINFO_APP":
        processNeighbourInfo(packet["from"], packet["decoded"]["neighborinfo"])

    elif portnum == "TEXT_MESSAGE_APP":
        processTextMessage(packet["from"], packet["to"], packet["decoded"]["text"])

    elif portnum == "ROUTING_APP":
        logging.info("[ROUTING ]")
        logging.debug(f"Received: {packet}")

    else:
        logging.info(packet["decoded"]["portnum"])
        logging.info(f"Received unknown: {packet}")


def main():
    global nodes
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    signal.signal(signal.SIGINT, cleanExit)
    mesh = None
    mqttclient = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=cliargs.mqtt_clientid, clean_session=True, userdata=None)

    if cliargs.ble:
        # we're using a BLE connection
        mesh = meshtastic.ble_interface.BLEInterface(address="any")
    elif cliargs.port is not None and cliargs.port[0] == '/':
        # we're using a serial connection
        mesh = meshtastic.serial_interface.SerialInterface(devPath=cliargs.port)
    elif cliargs.port is not None and cliargs.port[0].isnumeric():
        # we have an IP address, use TCP.
        mesh = meshtastic.tcp_interface.TCPInterface(hostname=cliargs.port)

    if mesh is not None:
        me = mesh.nodesByNum[mesh.myInfo.my_node_num]
        # no MQTT map reports connected directly to the local mesh, enable other packets
        cliargs.map_reports_only = False
        logging.info("Connected to [%s] %s\n" % (me["user"]["shortName"], me["user"]["longName"]))
        pub.subscribe(onReceive, "meshtastic.receive")
    else:
        logging.info("No mesh connection defined with --port or --ble. Using MQTT.")
        mqttclient.username_pw_set(cliargs.mqtt_user, cliargs.mqtt_pass)
        mqttclient.connect(cliargs.mqtt_host, cliargs.mqtt_port)
        mqttclient.subscribe(cliargs.mqtt_topic, 0)
        mqttclient.on_message = onReceiveMQTT
        mqttclient.loop_start()


    if cliargs.exclusive:
        try:
            with open(cliargs.exclusive, 'r') as exfile:
                for line in exfile:
                    mynodes.append(int(line.split()[0]))

        except FileNotFoundError:
            logging.error("Exclusive node list not found. Using all nodes.")

    try:
        with open('nodes.db', 'rb') as file:
            nodes = pickle.load(file)
            logging.info("Loaded %d nodes" % len(nodes))
    except FileNotFoundError:
        nodes = {}
        with open('nodes.db', 'wb') as file:
            pickle.dump(nodes, file)
    except pickle.UnpicklingError:
        logging.error("Invalid nodes database")
        nodes = {}
    except EOFError:
        logging.error("Invalid nodes database")
        nodes = {}

    cleanData()
    schedule.every(15).minutes.do(cleanData)

    # start geoJSON API
    if "FLASK_RUN_FROM_CLI" in os.environ.keys():
        del os.environ["FLASK_RUN_FROM_CLI"]
    mrh.run()

    while True:
        schedule.run_pending()
        time.sleep(1000)

    if mesh is not None:
        mesh.close()

    mqttclient.loop_stop()

if __name__ == "__main__":
    sys.exit(main())
