import requests
import math
import time

def get_new_lat_lon(lat, lon, dx, dy):
	# dirty hack: https://gis.stackexchange.com/a/2964
	return (lat + dx/111111, lon + dy/(111111*math.cos(lat)))

# Center of VIC
curr_loc = (-36.787728, 144.689149)
curr_r = 200000

def check_surrounds(lat, lon, r):
	for (dx, dy) in [(0,0),(-r/2,-r/2),(-r/2,0),(-r/2,r/2),(0,-r/2),(0,r/2),(r/2,-r/2),(r/2,0),(r/2,r/2)]:
		llat, llon = get_new_lat_lon(lat, lon, dx, dy)
		if check_loc(llat, llon, r):
			return llat, llon

def check_loc(lat, lon, rr):
	data = {
		"device": {
			"phoneNumber": "0491578888"
		},
		"area": {
			"radius": rr,
			"center": {
				"latitude": lat,
				"longitude": lon
			}
		}
	}
	r = requests.post('http://127.0.0.1:8000/verify', json=data)
	if "error" in r.json() and "Rate limit exceeded" in r.json()["error"]:
		print('Rate limit exceeded, retrying in 65 seconds...')
		time.sleep(65)
		return check_loc(lat, lon, rr)
	return r.json()["verificationResult"] == "TRUE"

print(curr_loc, curr_r)
while curr_r >= 2000:
	curr_loc = check_surrounds(*curr_loc, curr_r)
	curr_r = int(curr_r / 1.5)
	print(curr_loc, curr_r)