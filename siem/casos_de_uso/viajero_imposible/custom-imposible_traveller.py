#!/var/ossec/framework/python/bin/python3

import json
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import datetime
from geopy.distance import geodesic
import requests
import sqlite3

# Global vars
SOCKET_ADDR = '/var/ossec/queue/sockets/queue'
BD = '/var/ossec/var/db/DB_Imposible_traveller.db'

def main():
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)

        # Read alerts.json
        alert_file = open(sys.argv[1])
        alert_json = json.loads(alert_file.read())
        alert_file.close()

        alert_timestamp = alert_json['timestamp']

        # Posibles srcip
        posibles_srcip = ['srcip', 'src_ip', 'remip']
        alert_srcip = None
        for key in alert_json.get('data', {}):
            if key in posibles_srcip:
                alert_srcip = alert_json['data'][key]
                break

        if alert_srcip is None:
            # No IP, no party
            with open('/var/ossec/logs/integrations.log', "a") as file:
                file.write(f'{datetime.now().isoformat()} No srcip found in alert data\n')
            return

        alert_user = alert_json['data'].get('dstuser')
        if not alert_user:
            with open('/var/ossec/logs/integrations.log', "a") as file:
                file.write(f'{datetime.now().isoformat()} No dstuser found in alert data\n')
            return

        # IP-API info
        new_event = query_api(alert_srcip)
        if not new_event:
            with open('/var/ossec/logs/integrations.log', "a") as file:
                file.write(f'{datetime.now().isoformat()} GeoIP query failed for {alert_srcip}\n')
            return

        # new_event = (country, city, regionName, lat, lon)
        coords_new_event = (new_event[3], new_event[4])

        # Read database
        conn = sqlite3.connect(BD)
        cursor = conn.cursor()

        cursor.execute('''
        SELECT timestamp, user, srcip, lat, lon, country, city, regionName
        FROM logs
        WHERE user = ?
        ''', (alert_user,))

        user_in_db = cursor.fetchone()

        # If user exist in db, check if it possible to travel from point A to B
        if user_in_db:
            # user_in_db = (timestamp, user, srcip, lat, lon, country, city, regionName)
            coords_existent_event = (user_in_db[3], user_in_db[4])

            # Impossible traveller
            if not is_possible_travell(user_in_db[0],
                                       alert_timestamp,
                                       coords_existent_event,
                                       coords_new_event):

                msg = {
                    "Event": "The user established a VPN connection from point A and then from point B in a physically impossible time",
                    "User": alert_user,
                    "Timestamp first VPN connection": user_in_db[0],
                    "Country first VPN connection": user_in_db[5],
                    "City first VPN connection": user_in_db[6],
                    "Region first VPN connection": user_in_db[7],
                    "IP first VPN connection": user_in_db[2],
                    "Latitud first VPN connection": user_in_db[3],
                    "Longitud first VPN connection": user_in_db[4],
                    "Timestamp new VPN connection": alert_timestamp,
                    "Country new VPN connection": new_event[0],
                    "City new VPN connection": new_event[1],
                    "Region new VPN connection": new_event[2],
                    "IP new VPN connection": alert_srcip,
                    "Latitud new VPN connection": new_event[3],
                    "Longitud new VPN connection": new_event[4],
                    "Event ID": "1"
                }

                send_to_wazuh(sock, msg)

            # Same user, different country, but travel time reasonable
            elif user_in_db[5] != new_event[0]:

                msg = {
                    "Event": "The user established a VPN connection from one country and then from another different country in reasonable times, validate with client",
                    "User": alert_user,
                    "Timestamp first VPN connection": user_in_db[0],
                    "Country first VPN connection": user_in_db[5],
                    "City first VPN connection": user_in_db[6],
                    "Region first VPN connection": user_in_db[7],
                    "IP first VPN connection": user_in_db[2],
                    "Latitud first VPN connection": user_in_db[3],
                    "Longitud first VPN connection": user_in_db[4],
                    "Timestamp new VPN connection": alert_timestamp,
                    "Country new VPN connection": new_event[0],
                    "City new VPN connection": new_event[1],
                    "Region new VPN connection": new_event[2],
                    "IP new VPN connection": alert_srcip,
                    "Latitud new VPN connection": new_event[3],
                    "Longitud new VPN connection": new_event[4],
                    "Event ID": "2"
                }

                send_to_wazuh(sock, msg)

            # Finally, update with new event
            cursor.execute('''
            UPDATE logs
            SET timestamp = ?, srcip = ?, lat = ?, lon = ?, country = ?, city = ?, regionName = ?
            WHERE user = ?
            ''', (alert_timestamp,
                  alert_srcip,
                  new_event[3],
                  new_event[4],
                  new_event[0],
                  new_event[1],
                  new_event[2],
                  alert_user))

            with open('/var/ossec/logs/integrations.log', "a") as file:
                file.write(f'{datetime.now().isoformat()} User {alert_user} updated\n')

        else:
            # First time we see this user
            cursor.execute('''
            INSERT INTO logs (timestamp, user, srcip, country, city, regionName, lat, lon) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (alert_timestamp,
                  alert_user,
                  alert_srcip,
                  new_event[0],
                  new_event[1],
                  new_event[2],
                  new_event[3],
                  new_event[4]))

            with open('/var/ossec/logs/integrations.log', "a") as file:
                file.write(f'{datetime.now().isoformat()} User {alert_user} added to database\n')

        conn.commit()
        conn.close()

    except Exception as e:
        with open('/var/ossec/logs/integrations.log', "a") as file:
            file.write(f'{datetime.now().isoformat()} Exception: {repr(e)}\n')
    finally:
        try:
            sock.close()
        except Exception:
            pass

def send_to_wazuh(sock, msg_dict):
    """
    Recibe un dict Python y lo envía a Wazuh como JSON compacto,
    para que pueda ser parseado por el JSON_Decoder.
    """
    try:
        json_msg = json.dumps(msg_dict, ensure_ascii=False, separators=(",", ":"))
    except Exception as e:
        # Fallback por si algo muy raro pasa al serializar
        json_msg = json.dumps(
            {"Event": "error_encoding_impossible_traveller_msg",
             "original_error": repr(e)},
            ensure_ascii=False,
            separators=(",", ":")
        )

    string = f'1:Imposible_traveller_VPN:{json_msg}'
    sock.send(string.encode())

    with open('/var/ossec/logs/integrations.log', "a") as file:
        file.write(f'{datetime.now().isoformat()} Alert generated {string}\n')

# Function to calculate if it is possible to travel between two places with the given time
def is_possible_travell(tiempo_a, tiempo_b, coords_a, coords_b):
    # Calculate distance between points A and B using geopy (geodesic)
    distance = geodesic(coords_a, coords_b).kilometers

    # Calculate the time difference in hours
    fmt = "%Y-%m-%dT%H:%M:%S.%f%z"  # Date and time format
    time_a_dt = datetime.strptime(tiempo_a, fmt)
    time_b_dt = datetime.strptime(tiempo_b, fmt)
    delta_time = abs((time_b_dt - time_a_dt).total_seconds() / 3600)

    velocity = 800  # Average airplane speed in km/h

    # Calculate the time required to travel the distance at the given speed
    time_necessary = distance / velocity

    # Check if the trip is possible
    return delta_time >= time_necessary

def query_api(ip):
    url = f'http://ip-api.com/json/{ip}?fields=country,regionName,city,lat,lon,query'
    response = requests.get(url, timeout=5)

    if response.status_code == 200:
        data = response.json()
        return data['country'], data['city'], data['regionName'], data['lat'], data['lon']
    else:
        return None

if __name__ == "__main__":
    main()
