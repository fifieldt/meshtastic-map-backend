from flask import Flask, Response
from jinja2 import Template
import logging
import json

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

class MapRequestHandler:

    def __init__(self, nodes, mynodes, lat, lon, zoom, geojson, exclusive, *args, **kwargs):
        self.app = Flask(__name__)
        self.nodes = nodes
        self.mappage = ""
        self.mynodes = mynodes
        self.exclusive = exclusive
        self.app.add_url_rule("/", 'index', self.debug_map)
        self.app.add_url_rule("/map", 'map', self.debug_map)
        self.app.add_url_rule("/multipoint", 'multipoint', self.multipoint_json)
        self.app.add_url_rule("/links", 'links', self.links_json)
        self.app.add_url_rule("/nodes", 'nodes', self.nodes_json)
        with open('map.html', 'r') as file:
           self.mappage = Template(file.read()).render(latitude=lat,
                                                       longitude=lon,
                                                       zoom=zoom,
                                                       geojson=geojson)

    def getApp(self):
        return self.app

    def debug_map(self):
        r = Response(response=self.mappage.encode(encoding='utf-8'), mimetype="text/html")
        r.headers.add('Referrer-Policy', 'no-referrer')
        r.headers.add('Access-Control-Allow-Origin', '*')
        return r

    def multipoint_json(self):
        r = Response(response=self.nodesToJSON(multipoint=True).encode(encoding='utf_8'), mimetype="application/json")
        r.headers.add('Referrer-Policy', 'no-referrer')
        r.headers.add('Access-Control-Allow-Origin', '*')
        return r

    def links_json(self):
        r = Response(response=self.neighboursToJSON().encode(encoding='utf_8'), mimetype="application/json")
        r.headers.add('Referrer-Policy', 'no-referrer')
        r.headers.add('Access-Control-Allow-Origin', '*')
        return r

    def nodes_json(self):
        r = Response(response=self.nodesToJSON().encode(encoding='utf_8'), mimetype="application/json")
        r.headers.add('Referrer-Policy', 'no-referrer')
        r.headers.add('Access-Control-Allow-Origin', '*')
        return r


    def nodesToJSON(self, multipoint=False):
        features = []

        for node in self.nodes.keys():
            if self.nodes[node].getLatitude() == 0:
                continue
            if self.exclusive and node not in self.mynodes:
                continue
            if multipoint:
                if len(self.nodes[node].positions) > 1:
                    features.append(self.nodes[node].toMultiPoint())
            else:
                features.append(self.nodes[node].toFeature(self.nodes))

        features_json = {"type":"FeatureCollection", "features": features}
        return json.dumps(features_json)


    def neighboursToJSON(self):
        features = []

        for node in self.nodes.keys():
            if self.exclusive and node not in self.mynodes:
                continue
            links  = self.nodes[node].getLinks(self.nodes)
            for link in links:
                features.append(link)

        features_json = {"type":"FeatureCollection", "features": features}

        return json.dumps(features_json)


    def run(self, host="0.0.0.0", port=8100):
        self.app.run(host=host, port=port)
