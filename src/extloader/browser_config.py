from dataclasses import dataclass
from typing import Dict, List
import os
from pathlib import Path

@dataclass
class BrowserConfig:
    name: str
    seed: bytes
    default_location: int
    preferences_path: str
    secure_preferences_path: str
    
    def get_user_data_path(self, username: str) -> str:
        base_path = os.path.expanduser(f"~{username}")
        return os.path.join(base_path, self.preferences_path)

class BrowserConfigurator:
    CHROME_SEED = b'\xe7H\xf36\xd8^\xa5\xf9\xdc\xdf%\xd8\xf3G\xa6[L\xdffv\x00\xf0-\xf6rJ*\xf1\x8a!-&\xb7\x88\xa2P\x86\x91\x0c\xf3\xa9\x03\x13ihq\xf3\xdc\x05\x8270\xc9\x1d\xf8\xba\\O\xd9\xc8\x84\xb5\x05\xa8'
    EDGE_SEED = b''
    BRAVE_SEED = b''
    CHROMIUM_SEED = b''
    VIVALDI_SEED = b''
    OPERA_SEED = b''

    @staticmethod
    def get_browser_configs() -> Dict[str, BrowserConfig]:
        return {
            "chrome": BrowserConfig(
                name="Chrome",
                seed=BrowserConfigurator.CHROME_SEED,
                default_location=4,
                preferences_path="AppData/Local/Google/Chrome/User Data/Default/Preferences",
                secure_preferences_path="AppData/Local/Google/Chrome/User Data/Default/Secure Preferences"
            ),
            "edge": BrowserConfig(
                name="Microsoft Edge",
                seed=BrowserConfigurator.EDGE_SEED,
                default_location=4,
                preferences_path="AppData/Local/Microsoft/Edge/User Data/Default/Preferences",
                secure_preferences_path="AppData/Local/Microsoft/Edge/User Data/Default/Secure Preferences"
            ),
            "brave": BrowserConfig(
                name="Brave",
                seed=BrowserConfigurator.BRAVE_SEED,
                default_location=4,
                preferences_path="AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Preferences",
                secure_preferences_path="AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Secure Preferences"
            ),
            "chromium": BrowserConfig(
                name="Chromium",
                seed=BrowserConfigurator.CHROMIUM_SEED,
                default_location=4,
                preferences_path="AppData/Local/Chromium/User Data/Default/Preferences",
                secure_preferences_path="AppData/Local/Chromium/User Data/Default/Secure Preferences"
            ),
            "vivaldi": BrowserConfig(
                name="Vivaldi",
                seed=BrowserConfigurator.VIVALDI_SEED,
                default_location=4,
                preferences_path="AppData/Local/Vivaldi/User Data/Default/Preferences",
                secure_preferences_path="AppData/Local/Vivaldi/User Data/Default/Secure Preferences"
            ),
            # FIXME: Opera behaves differently, and is not stable
            "opera": BrowserConfig(
                name="Opera",
                seed=BrowserConfigurator.OPERA_SEED,
                default_location=4,
                preferences_path="AppData/Roaming/Opera Software/Opera Stable/Default/Preferences",
                secure_preferences_path="AppData/Roaming/Opera Software/Opera Stable/Default/Secure Preferences"
            )
        }

    @staticmethod
    def get_installed_browsers(username: str) -> List[str]:
        configs = BrowserConfigurator.get_browser_configs()
        installed = []
        
        for browser_id, config in configs.items():
            prefs_path = config.get_user_data_path(username)
            if os.path.exists(prefs_path):
                installed.append(browser_id)
                
        return installed 