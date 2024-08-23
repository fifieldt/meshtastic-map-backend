# Meshtastic Map Backend
The Meshtastic Map Backend is designed to recieve meshtastic packets from the mesh
or an MQTT server, process it, and offer a geoJSON API that can be consumed by
mapping front-ends.


## Connecting
There are two main modes, Local Mesh and MQTT.

### Direct Mesh Connection
If you have a Meshtastic Device connected to your PC, you can use the Meshtastic
Serial Interface to receive packets. Start the backend using the `--port` or `--ble`
arguments to connect to the device.

`./backend.py --port /dev/ttyACM0`

### MQTT

To gather data from an MQTT server instead, specify the standard set of variables for an
MQTT connection:

`./backend.py --mqtt-host mqtt.meshtastic.org --mqtt-user meshdev --mqtt-pass large4cats --mqtt-topic msh/TW/#`

## API Endpoints

By default, an HTTP server will run at port 8100, and offer the following endpoints:

* /nodes - GeoJSON FeatureCollection with each discovered node with its latest position as a Point
* /links - GeoJSON FeatureCollection with each discovered neighour relationship between nodes as a LineString
* /multipoint - GeoJson FeatureCollection with tracks and times of node positions

Each node listed in /nodes may have the following `properties`:
* name
* shortname
* objectid
* batterylevel
* neighbours
* positionprecision
* lastupdated

## Other Features

### Exclusive mode
If you only want to map your own nodes, list each node id (one-per-line) in a file and pass that file
to the `--exclusive` parameter.

### Debug Map
`/map` provides a basic leaflet.js map that show nodes and links, primarily for debugging.
You can set the center of that map by specifying `--latitude` and `--longitude`, in addition to the
zoom level (`--zoom`).

If you want to use an alternative source for the GeoJSON API endpoint, you can specify a URL using `--geoJSON`.


### Map Reports Only
By default, when using MQTT, the backend only processes `MAP_REPORT_APP` packets. If you are using a
private MQTT server for your local community, you can disable this limitation by specifying 
`--map-reports-only False`.
