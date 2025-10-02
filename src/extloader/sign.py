import hmac
import json
import hashlib
import logging
import os
from .browser_config import BrowserConfigurator

log = logging.getLogger("rich")

class PreferencesManager:
    def __init__(self, browser_id: str = "chrome"):
        self.browser_config = BrowserConfigurator.get_browser_configs()[browser_id]
        self.seed = self.browser_config.seed
        self.default_location = self.browser_config.default_location

    @staticmethod
    def remove_empty(d):
        if isinstance(d, dict):
            keys_to_delete = []
            for k, v in d.items():
                if isinstance(v, (dict, list)):
                    PreferencesManager.remove_empty(v)
                if not v and v not in [False, 0]:
                    keys_to_delete.append(k)
            for k in keys_to_delete:
                del d[k]
        elif isinstance(d, list):
            d[:] = [item for item in d if item or item in [False, 0]]

    @staticmethod
    def calculate_hmac(value_as_string, path, sid, seed):
        if isinstance(value_as_string, dict):
            PreferencesManager.remove_empty(value_as_string)
        
        json_value = json.dumps(value_as_string, separators=(',', ':'), ensure_ascii=False)
        json_value = json_value.replace('<', '\\u003C').replace('\\u2122', '™')
        sid = '-'.join(sid.split('-')[:-1])
        log.debug(f"SID used for HMAC: {sid}")
        
        message = sid + path + json_value
        hash_obj = hmac.new(seed, message.encode("utf-8"), hashlib.sha256)
        return hash_obj.hexdigest().upper()

    @staticmethod
    def calc_supermac(data, sid, seed):
        sid = '-'.join(sid.split('-')[:-1])
        super_msg = sid + json.dumps(data['protection']['macs'], separators=(',', ':'))
        hash_obj = hmac.new(seed, super_msg.encode("utf-8"), hashlib.sha256)
        return hash_obj.hexdigest().upper()

    @staticmethod
    def get_extension_id():
        keys_file = 'extension_keys.json'
        if not os.path.exists(keys_file):
            log.error(f"Extension keys not found. Please run 'sign' command first.")
            return None
        
        with open(keys_file, 'r', encoding='utf-8') as f:
            keys = json.load(f)
        return keys['crx_id']

    def create_base_extension_json(self, absolute_extension_path):
        return {
            "active_permissions": {
                "api": [
                    "activeTab", "cookies", "debugger", "webNavigation", 
                    "webRequest", "scripting"
                ],
                "explicit_host": ["<all_urls>"],
                "manifest_permissions": [],
                "scriptable_host": ["<all_urls>"]
            },
            "commands": {},
            "content_settings": [],
            "creation_flags": 38,
            "filtered_service_worker_events": {
                "webNavigation.onCompleted": [{}]
            },
            "first_install_time": "13378928502176646",
            "from_webstore": False,
            "granted_permissions": {
                "api": [
                    "activeTab", "cookies", "debugger", "webNavigation", 
                    "webRequest", "scripting"
                ],
                "explicit_host": ["<all_urls>"],
                "manifest_permissions": [],
                "scriptable_host": ["<all_urls>"]
            },
            "incognito_content_settings": [],
            "incognito_preferences": {},
            "last_update_time": "13378928502176646",
            "location": self.default_location,
            "newAllowFileAccess": True,
            "path": absolute_extension_path,
            "preferences": {},
            "regular_only_preferences": {},
            "state": 1
        }

def update_secure_preferences(secure_prefs, absolute_extension_path, target_sid, manifest_content, browser_id="chrome"):
    log.debug(f"=== Starting Secure Preferences Update ===")
    log.debug(f"Browser ID: {browser_id}")
    log.debug(f"Target SID: {target_sid}")
    log.debug(f"Extension Path: {absolute_extension_path}")
    
    prefs_manager = PreferencesManager(browser_id)
    log.debug(f"Using browser config: {prefs_manager.browser_config.__dict__}")
    log.debug(f"Browser seed: {prefs_manager.seed.hex()}")
    
    extension_id = prefs_manager.get_extension_id()
    if not extension_id:
        log.error("Failed to get extension ID")
        return None

    data = json.loads(secure_prefs)
    log.debug(f"Using extension ID: {extension_id}")
    
    extension_json = prefs_manager.create_base_extension_json(absolute_extension_path)
    log.debug(f"Created base extension JSON with location: {extension_json.get('location')}")
    
    try:
        manifest = json.loads(manifest_content)
        extension_json['version'] = manifest.get('version', '1.0')
        log.debug(f"Added version from manifest: {extension_json['version']}")
    except json.JSONDecodeError:
        log.error("Failed to parse manifest.json")
        return None

    # Ensure extensions settings structure exists
    if "extensions" not in data:
        data["extensions"] = {"settings": {}}
    elif "settings" not in data["extensions"]:
        data["extensions"]["settings"] = {}
        
    # Add developer mode setting (Chrome v134+)
    if "ui" not in data["extensions"]:
        data["extensions"]["ui"] = {}
    data["extensions"]["ui"]["developer_mode"] = True
    
    # Add extension to settings
    data["extensions"]["settings"][extension_id] = extension_json
    
    # Ensure protection structure exists
    if "protection" not in data:
        data["protection"] = {"macs": {"extensions": {"settings": {}}}}
    elif "macs" not in data["protection"]:
        data["protection"]["macs"] = {"extensions": {"settings": {}}}
    elif "extensions" not in data["protection"]["macs"]:
        data["protection"]["macs"]["extensions"] = {"settings": {}}
    elif "settings" not in data["protection"]["macs"]["extensions"]:
        data["protection"]["macs"]["extensions"]["settings"] = {}
    
    # Add ui protection structure if not exists
    if "ui" not in data["protection"]:
        data["protection"]["ui"] = {}
    
    # Calculate extension HMAC
    path = f"extensions.settings.{extension_id}"
    macs = prefs_manager.calculate_hmac(extension_json, path, target_sid, prefs_manager.seed)
    log.debug(f"Generated ext MAC: {macs}")
    data["protection"]["macs"]["extensions"]["settings"][extension_id] = macs
    
    # Calculate developer mode HMAC (Chrome v134+)
    dev_mode_path = "extensions.ui.developer_mode"
    dev_mode_mac = prefs_manager.calculate_hmac(True, dev_mode_path, target_sid, prefs_manager.seed)
    log.debug(f"Generated developer mode MAC: {dev_mode_mac}")
    data["protection"]["ui"]["developer_mode"] = dev_mode_mac
    
    # Calculate super MAC
    log.debug("=== Calculating super MAC ===")
    supermac = prefs_manager.calc_supermac(data, target_sid, prefs_manager.seed)
    log.debug(f"Generated super MAC: {supermac}")
    data["protection"]["super_mac"] = supermac
    
    log.debug("=== Secure Preferences Update Complete ===")
    return json.dumps(data, ensure_ascii=False).encode('utf-8')

def update_preferences(preferences, absolute_extension_path, target_sid, manifest_content, browser_id="chrome"):
    log.debug(f"Updating Preferences file")
    
    prefs_manager = PreferencesManager(browser_id)
    extension_id = prefs_manager.get_extension_id()
    if not extension_id:
        return None

    data = json.loads(preferences)
    log.debug(f"Using extension ID: {extension_id}")

    # Initialize required structures
    if "extensions" not in data:
        data["extensions"] = {"settings": {}}
    elif "settings" not in data["extensions"]:
        data["extensions"]["settings"] = {}

    # Add developer mode setting (Chrome v134+)
    if "ui" not in data["extensions"]:
        data["extensions"]["ui"] = {}
    data["extensions"]["ui"]["developer_mode"] = True

    if "protection" not in data:
        data["protection"] = {"macs": {"extensions": {"settings": {}}}}
    elif "macs" not in data["protection"]:
        data["protection"]["macs"] = {"extensions": {"settings": {}}}
    elif "extensions" not in data["protection"]["macs"]:
        data["protection"]["macs"]["extensions"] = {"settings": {}}
    elif "settings" not in data["protection"]["macs"]["extensions"]:
        data["protection"]["macs"]["extensions"]["settings"] = {}

    # Add ui protection structure
    if "ui" not in data["protection"]:
        data["protection"]["ui"] = {}

    extension_json = prefs_manager.create_base_extension_json(absolute_extension_path)
    try:
        manifest = json.loads(manifest_content)
        extension_json['version'] = manifest.get('version', '1.0')
    except json.JSONDecodeError:
        log.error("Failed to parse manifest.json")
        return None

    data["extensions"]["settings"][extension_id] = extension_json
    
    # Calculate extension HMAC
    path = f"extensions.settings.{extension_id}"
    mac = prefs_manager.calculate_hmac(extension_json, path, target_sid, prefs_manager.seed)
    data["protection"]["macs"]["extensions"]["settings"][extension_id] = mac
    log.debug(f"Added extension {extension_id} to Preferences with MAC: {mac}")
    
    # Calculate developer mode HMAC (Chrome v134+)
    dev_mode_path = "extensions.ui.developer_mode"
    dev_mode_mac = prefs_manager.calculate_hmac(True, dev_mode_path, target_sid, prefs_manager.seed)
    log.debug(f"Generated developer mode MAC: {dev_mode_mac}")
    data["protection"]["ui"]["developer_mode"] = dev_mode_mac

    return json.dumps(data, ensure_ascii=False).encode('utf-8')
