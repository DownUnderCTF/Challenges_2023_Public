from typing import Union

from fastapi import FastAPI
from pydantic import Field, BaseModel
from typing_extensions import Annotated

from starlette.requests import Request

from slowapi.errors import RateLimitExceeded
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

import geopy.distance
import re
import time

USER_PHONE = ['+61491578888', '0491578888']
USER_LOCATION = (-36.44982023052729, 146.4307814254105)

class Device(BaseModel):
    phoneNumber: str

class Point(BaseModel):
    latitude: float
    longitude: float

class Circle(BaseModel):
    areaType: str = "Circle"
    center: Point
    radius: Annotated[int, Field(ge=2000, le=200000)]

class VerifyLocationRequest(BaseModel):
    device: Device
    area: Circle
    maxAge: Annotated[int, Field(ge=60, le=120)] = 120

class VerifyLocationResponse(BaseModel):
    lastLocationTime: Union[str, None]
    verificationResult: str

app = FastAPI()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/verify")
@limiter.limit("10/minute")
async def verify(body: VerifyLocationRequest, request: Request) -> VerifyLocationResponse:
    """
    This API provides the customer with the ability to verify the location of a device. 

    # Introduction

    Customers are able to verify whether the location of certain user device is within the area specified. Currently the only area supported is a circle determined by the provided coordinates (latitude and longitude) and some expected accuracy (radius).

    The verification result depends on the network's ability and accuracy to locate the device at the requested area. 
    
    * The network locates the device within the requested area, the verification result is `TRUE`.
    * The requested area may not match the area where the network locates the device. In this case, the verification result is `FALSE` . 
    * The requested area partially match the area where the network locates the device, the verification result is `PARTIAL`. In this case, a `match_rate` could be included in the response, indicating an estimation of the likelihood of the match in percent.
    * Lastly, the network may not be able to locate the device. In this case, the verification result is `UNKNOWN`

    Location Verification could be useful in scenarios such as:

    - Fraud protection to ensure a given user is located in the region, country or location claimed for financial transactions
    - Verify the GPS coordinates reported by the app on a device to ensure the GPS was not faked e.g. for content delivery with regional restrictions
    - Location-based advertising: trigger targeted advertising after verifying the user is in the area of interest
    - Smart Mobility (Vehicle/bikes renting): confirm the location of the device and the location of the vehicle/bike to guarantee they are rented correctly

    # Relevant terms and definitions

    * **Device**: A device refers to any physical entity that can connect to a network and participate in network communication.

    * **Area**: It specifies the geographical surface where a device may be physically located.

    * **Verification**: Process triggered in the API server to confirm or contradict the expectation assumed by the API client about the device location.

    # API Functionality

    The API exposes a single endpoint/operation:

    - Verify whether the device location is within a requested area, currently circle with center specified by the latitude and longitude, and radius specified by the accuracy. The operation returns a verification result and, optionally, a match rate estimation for the location verification in percent.

    # Further info and support

    (FAQs will be added in a later version of the documentation)
    """

    # Phone OK?
    if re.sub(r'[^0-9+]', '', body.device.phoneNumber) not in USER_PHONE:
        return {"lastLocationTime": None, "verificationResult": "UNKNOWN"}
    
    # Calc dist
    dist = geopy.distance.geodesic(USER_LOCATION, (body.area.center.latitude, body.area.center.longitude)).m
    res = "TRUE" if dist <= body.area.radius else "FALSE"
    lloc = time.ctime() if dist <= body.area.radius else None

    return {"lastLocationTime": lloc, "verificationResult": res}