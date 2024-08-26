from functools import partial
from http.server import HTTPServer, BaseHTTPRequestHandler
from jinja2 import Template
import logging
import json

class MapHTTPRequestHandler(BaseHTTPRequestHandler):

    def __init__(self, cliargs, nodes, mynodes, *args, **kwargs):
        self.cliargs = cliargs
        self.nodes = nodes
        self.mappage = ""
        self.mynodes = mynodes
        with open('map.html', 'r') as file:
           self.mappage = Template(file.read()).render(latitude=cliargs.latitude,
                                                       longitude=cliargs.longitude,
                                                       zoom=cliargs.zoom,
                                                       geojson=cliargs.geojson)
        super(MapHTTPRequestHandler, self).__init__(*args, **kwargs)

    def do_GET(self):
        if self.path == '/map':
            # Set the referrer policy header
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.send_header('Referrer-Policy', 'no-referrer')  # Change 'no-referrer' to your desired policy
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(self.mappage.encode(encoding='utf-8'))

        elif self.path == '/multipoint':
            # Set the referrer policy header
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Referrer-Policy', 'no-referrer')  # Change 'no-referrer' to your desired policy
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(self.nodesToJSON(multipoint=True).encode(encoding='utf_8'))
        elif self.path[0:6] == '/links':
            # Set the referrer policy header
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Referrer-Policy', 'no-referrer')  # Change 'no-referrer' to your desired policy
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(self.neighboursToJSON().encode(encoding='utf_8'))

        else:
            # Set the referrer policy header
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Referrer-Policy', 'no-referrer')  # Change 'no-referrer' to your desired policy
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(self.nodesToJSON().encode(encoding='utf_8'))

    def log_request(self, code):
        pass

    def nodesToJSON(self, multipoint=False):
        features = []

        for node in self.nodes.keys():
            if self.nodes[node].getLatitude() == 0:
                continue
            if self.cliargs.exclusive and node not in self.mynodes:
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
        neighbours_found = False

        for node in self.nodes.keys():
            if self.cliargs.exclusive and node not in self.mynodes:
                continue
            links  = self.nodes[node].getLinks(self.nodes)
            if len(links) > 0:
                features.append(links)
                neighbours_found = True

        if neighbours_found is False:
            features.append({})

        features_json = {"type":"FeatureCollection", "features": features}

        return json.dumps(features_json)



def run_server(cliargs, nodes, mynodes, port=8100):
    server_address = ('', port)
    httpd = HTTPServer(server_address, partial(MapHTTPRequestHandler, cliargs, nodes, mynodes))
    logging.info(f'Starting server on port {port}...')
    httpd.serve_forever()
