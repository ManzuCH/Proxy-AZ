import requests
import time
import json
import sys

# Constants for Microsoft Auth (Public Client)
# Azure CLI Client ID (Reliable fallback for Device Code Flow)
CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46" 


SCOPE = "XboxLive.Signin offline_access"

def device_flow_login():
    """
    Performs the Device Code Flow.
    Returns the Minecraft Access Token and Profile.
    """
    # 1. Get Device Code
    print("[Auth] Requesting Device Code...")
    # Try using 'common' tenant for broader compatibility
    resp = requests.post("https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode", data={
        "client_id": CLIENT_ID,
        "scope": SCOPE
    })
    
    # Fallback to manual input if device code fails
    if resp.status_code != 200:
        print(f"[!] Device Code Request failed: {resp.text}")
        print("[!] Falling back to MANUAL token input.")
        print("Please use a 3rd party tool or browser to get a Minecraft Access Token.")
        print("You can get one via https://msgraph.oauth.net/ (experimental) or check local launcher logs.")
        token = input("Paste your Minecraft Access Token: ").strip()
        if not token: raise Exception("No token provided")
        return authenticate_minecraft(token) # This assumes it's an MS token? 
        # Actually user needs to paste the FINAL Minecraft Token usually, OR the MS Token.
        # Let's assume they paste the Microsoft Token -> we do XBL/XSTS/MC.
        # OR they paste the MC Token directly.
        # Let's verify format. MC Token is usually JWT ~1KB. MS Token is also JWT.
        # Safer to ask for MS Token so we can refresh/get profile? 
        # But hardest part is getting MS Token.
        # If user pastes MC Token, we just fetch profile.
        
        # Let's try to interpret what they pasted.
        # If it works for profile fetch, it's an MC Token.
        try:
             return get_profile(token)
        except:
             # Assume it's MS Token
             return authenticate_minecraft(token)

    flow_data = resp.json()
    device_code = flow_data['device_code']
    user_code = flow_data['user_code']
    verification_uri = flow_data['verification_uri']
    interval = flow_data.get('interval', 5)
    
    print(f"\n[Auth] ==================================================")
    print(f"[Auth] Please visit: {verification_uri}")
    print(f"[Auth] Enter code:   {user_code}")
    print(f"[Auth] ==================================================\n")
    
    # 2. Poll for token
    print("[Auth] Waiting for login...", end='')
    while True:
        time.sleep(interval)
        print(".", end='', flush=True)
        resp = requests.post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": CLIENT_ID,
            "device_code": device_code
        })
        
        if resp.status_code == 200:
            print(" Done!")
            return authenticate_minecraft(resp.json()['access_token'])
        
        err = resp.json().get('error')
        if err == 'authorization_pending':
            continue
        elif err == 'expired_token':
            raise Exception("Timeout waiting for login.")
        else:
            raise Exception(f"Auth error: {resp.text}")

def authenticate_minecraft(ms_access_token):
    # 3. Exchange for XBL Token
    print("[Auth] Authenticating with Xbox Live...")
    xbl_resp = requests.post("https://user.auth.xboxlive.com/user/authenticate", json={
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": f"d={ms_access_token}"
        },
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT"
    })
    if xbl_resp.status_code != 200: raise Exception(f"XBL Auth failed: {xbl_resp.text}")
    xbl_data = xbl_resp.json()
    xbl_token = xbl_data['Token']
    uhs = xbl_data['DisplayClaims']['xui'][0]['uhs']
    
    # 4. Exchange for XSTS Token
    print("[Auth] Authenticating with XSTS...")
    xsts_resp = requests.post("https://xsts.auth.xboxlive.com/xsts/authorize", json={
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [xbl_token]
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT"
    })
    if xsts_resp.status_code != 200: raise Exception(f"XSTS Auth failed: {xsts_resp.text}")
    xsts_token = xsts_resp.json()['Token']
    
    # 5. Login to Minecraft
    print("[Auth] Getting Minecraft Access Token...")
    mc_resp = requests.post("https://api.minecraftservices.com/authentication/login_with_xbox", json={
        "identityToken": f"XBL3.0 x={uhs};{xsts_token}"
    })
    if mc_resp.status_code != 200: raise Exception(f"Minecraft Login failed: {mc_resp.text}")
    mc_token = mc_resp.json()['access_token']
    
    # 6. Get Profile
    print("[Auth] Fetching Profile...")
    profile_resp = requests.get("https://api.minecraftservices.com/minecraft/profile", headers={
        "Authorization": f"Bearer {mc_token}"
    })
    if profile_resp.status_code != 200: raise Exception(f"Profile fetch failed: {profile_resp.text}")
    
    profile = profile_resp.json()
    print(f"[Auth] Logged in as: {profile['name']} ({profile['id']})")
    
    return mc_token, profile['name'], profile['id']

def join_server(access_token, selected_profile, server_id, shared_secret, public_key):
    """
    Tells Mojang's Session Server that we have joined the server.
    server_id must be the hash coming from the proxy (Real Server ID).
    """
    # Calculate the hash manually? No, the caller should pass the calculated hash (hexdigest).
    # Wait, the 'serverId' in the join payload is usually the hash.
    
    payload = {
        "accessToken": access_token,
        "selectedProfile": selected_profile,
        "serverId": server_id
    }
    
    print(f"[Auth] Sending Join Request to Mojang for ServerHash: {server_id}")
    resp = requests.post("https://sessionserver.mojang.com/session/minecraft/join", json=payload)
    
    if resp.status_code == 204:
        print("[Auth] Join successful!")
        return True
    else:
        print(f"[Auth] Join failed: {resp.status_code} {resp.text}")
        return False

def get_profile(mc_token):
    # Helper to just get profile from MC Token
    print("[Auth] Fetching Profile with provided token...")
    profile_resp = requests.get("https://api.minecraftservices.com/minecraft/profile", headers={
        "Authorization": f"Bearer {mc_token}"
    })
    if profile_resp.status_code != 200: 
        raise Exception(f"Profile fetch failed: {profile_resp.text}")
    
    profile = profile_resp.json()
    print(f"[Auth] Logged in as: {profile['name']} ({profile['id']})")
    return mc_token, profile['name'], profile['id']
