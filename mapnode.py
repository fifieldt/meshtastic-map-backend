from datetime import datetime
import json
import logging
from math import sin, cos, sqrt, atan2, radians
import timeago


class MapNode:

    def __init__(self, nodeid, name="UNKN", longname="UNKNOWN"):
        self.nodeid = nodeid
        self.name = name
        self.longname = longname
        self.latitude = 0.0
        self.longitude = 0.0
        self.altitude = 0
        self.batterylevel = 0
        self.neighbours = {}
        self.positionprecision = 0
        self.positions = {}
        self.lastupdated = datetime.now().timestamp()

    def __str__(self):
        return ("[%s] %s @ %f, %f %dm 🔋%d%%\nNeighbours: %s\nPositions: %s" % (self.name, self.longname,
                                                                                self.latitude, self.longitude,
                                                                                self.altitude, self.batterylevel,
                                                                                self.neighbours, self.positions))

    def addNeighbour(self, neighbour=0, snr=0):
        if neighbour != 0:
            self.lastupdated = datetime.now().timestamp()
            self.neighbours[neighbour] = [snr, self.lastupdated]

    def getLastUpdated(self, style="pretty"):
        if style == "pretty":
            return timeago.format(datetime.fromtimestamp(self.lastupdated), datetime.now(), "en_short")
        elif style == "exact":
            return datetime.fromtimestamp(self.lastupdated).strftime("%m-%d %H:%M:%S")

        return self.lastupdated

    def clean(self, delta=172800):
        for i in list(self.neighbours):
            if (datetime.fromtimestamp(self.neighbours[i][1] + delta) < datetime.now()):
                del self.neighbours[i]
        for i in list(self.positions):
            if (datetime.fromtimestamp(i + delta) < datetime.now()):
                del self.positions[i]

    def getLatitude(self):
        return self.latitude

    def getLongitude(self):
        return self.longitude

    def getName(self):
        return self.name

    def getNeighbours(self, nodes, pretty=True):
        if pretty:
            if len(self.neighbours.keys()) == 0:
                return "-"
            else:
                returnstring = ""
            for i in self.neighbours.keys():
                if i not in nodes.keys():
                    returnstring += str(i)
                else:
                    returnstring += nodes[i].getName()
                returnstring += " " + str(self.neighbours[i][0]) + "dBm"
                returnstring += " " + timeago.format(self.neighbours[i][1], datetime.now(), "en_short")
                returnstring += "\n"
            return returnstring

        return self.neighbours

    def getNodeId(self):
        return self.nodeid

    def getSNRQuality(self, snr, toColour=False):
        if snr > -10:
            return "Great"
        elif snr >= -15:
            return "Good"
        elif snr >= -20:
            return "Fair"
        elif snr < -20:
            return "Poor"

    def getLinks(self, nodes):
        geojson = ""
        if self.latitude == 0 or self.longitude == 0:
            return geojson

        for i in self.neighbours.keys():
            try:
                if nodes[i].getLatitude() == 0 or nodes[i].getLongitude() == 0:
                    continue

                geojson += """
                {
                  "type": "Feature",
                  "properties": {
                    "name": """ + '"' + str(self.name) + "-" + nodes[i].getName() + """",
                    "snr": """ + '"' + str(self.neighbours[i][0]) + """",
                    "snr_qual": """ + '"' + self.getSNRQuality(self.neighbours[i][0]) + """",
                    "lastupdated": """ + '"' + timeago.format(self.neighbours[i][1], datetime.now(), "en_short") + """"
                  },
                  "geometry": {
                    "type": "LineString",
                    "coordinates": [[""" + str(self.longitude) + ", " + str(self.latitude) + """],
                                    [  """ + str(nodes[i].getLongitude()) + ", " + str(nodes[i].getLatitude()) + """]]
                  }
                },"""
            except KeyError as e:
                logging.error(repr(e))

        return geojson[:-1]


    def setMetrics(self, batterylevel=0):
        if batterylevel != 0:
            self.batterylevel = batterylevel
            self.lastupdated = datetime.now().timestamp()

    def setName(self, name=None, longname=None):
        if name is not None:
            self.name = name
        if longname is not None:
            self.longname = longname
        self.lastupdated = datetime.now().timestamp()

    """
    Uses the Haversine formula (accuracy +/- 0.5%) to find the distance in km from our node
    """
    def roughDistance(self, lat, long):
        # Approximate radius of earth in km
        R = 6373.0
        latdelta = radians(lat) - radians(self.latitude)
        londelta = radians(long) - radians(self.longitude)

        a = sin(latdelta / 2)**2 + cos(radians(self.latitude)) * cos(radians(lat)) * sin(londelta / 2)**2
        c = 2 * atan2(sqrt(a), sqrt(1 - a))
        return R * c


    def setPosition(self, latitude, longitude, altitude=0):
        # we moved more than 3km since last position - invalidate neighbours if they are older
        # than an hour
        if self.roughDistance(latitude, longitude) > 3.0:
            for i in list(self.neighbours):
                if datetime.fromtimestamp(self.neighbours[i][1] + 3600) < datetime.now():
                    del self.neighbours[i]

        self.latitude = latitude
        self.longitude = longitude
        if altitude != 0:
            self.altitude = altitude
        self.lastupdated = datetime.now().timestamp()
        self.positions[self.lastupdated] = [latitude, longitude]

    def toFeature(self, nodes):
        return """
        {
          "type": "Feature",
          "properties": {
            "name": """ + '"' + str(self.longname) + """",
            "shortname": """ + '"' + str(self.name) + """",
            "objectid": """ + '"' + str(self.nodeid) + """",
            "batterylevel": """ + '"' + str(self.batterylevel) + """",
            "neighbours": """ + '"' + self.getNeighbours(nodes).replace("\n", "<br />") + """",
            "lastupdated": """ + '"' + self.getLastUpdated() + """",
            "positionprecision": """ + '"' + str(self.positionprecision) + """"
          },
          "geometry": {
            "type": "Point",
            "coordinates": [""" + str(self.longitude) + ', ' + str(self.latitude) + """]
          }
        }"""

    def toMultiPoint(self):
        return """
        {
          "type": "Feature",
          "properties": {
            "name": """ + '"' + str(self.longname) + """",
            "shortname": """ + '"' + str(self.name) + """",
            "objectid": """ + '"' + str(self.nodeid) + """",
            "times": """ + json.dumps([datetime.fromtimestamp(key).strftime("%Y-%m-%d %H:%M:%S") for key in self.positions.keys()]) + """
          },
          "geometry": {
            "type": "LineString",
            "coordinates": """ + str([[item[1][1],item[1][0]] for item in self.positions.items()]) + """
          }
        }"""
