from util import Util
from time import sleep
import random
from curl_cffi import requests

config = Util.get_config()

SOLVER_KEY = config["solver_key"]

def get_token(roblox_session: requests.Session, blob, proxy, cookie):
    session = requests.Session(impersonate="chrome")
    
    payload = {
        "chrome_version":"132",
        "blob":blob,
        "api_key":SOLVER_KEY,
        "preset": "roblox_login",
        "custom_cookies":dict(cookie.split("=", 1) for cookie in cookie.split("; ") if "=" in cookie),
        "proxy": f"http://{proxy}"
    }

    response = session.post("https://solve.sxvm.co.uk/createTask", json=payload, timeout=120)
    
    if response.status_code == 402:
        print("Free solver is currently disabled come back later")
        return None
        
    response = response.json()
    task_id = response.get("task_id")

    if task_id == None:
        raise ValueError(f"Failed to get taskId, reason: {response['err']}")
    
    counter = 0

    while counter < 60:
        sleep(1)
        json = {'task_id':task_id, "api_key":SOLVER_KEY}
        solution = session.post(f"https://solve.sxvm.co.uk/getTask",json=json).json()
        
        if solution["status"] == "completed":
            return solution["captcha"]["token"]
        
        elif solution["status"] == "failed":
            return None
        
        counter += 1

    return None