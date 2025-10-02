from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb3structs import FILE_READ_DATA, FILE_WRITE_DATA, FILE_APPEND_DATA
from .utils import log

class SMBOperations:
    def __init__(self, target, username, password, domain):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.smb_conn = None
        self.tree_id = None

    def connect(self):
        try:
            self.smb_conn = SMBConnection(self.target, self.target, sess_port=445)
            self.smb_conn.login(self.username, self.password, self.domain)
            log.info("[green]SMB connection established successfully![/green]", extra={"markup": True})
            self.tree_id = self.smb_conn.connectTree("C$")
        except Exception as e:
            log.error(f"Failed to connect to {self.target} using SMB: {str(e)}")
            raise

    def disconnect(self):
        if self.smb_conn:
            self.smb_conn.close()

    def backup_file(self, remote_path, local_backup_path):
        try:
            file_id = self.smb_conn.openFile(self.tree_id, remote_path, desiredAccess=FILE_READ_DATA)
            file_content = self.smb_conn.readFile(self.tree_id, file_id)
            self.smb_conn.closeFile(self.tree_id, file_id)
            
            with open(local_backup_path, 'wb') as f:
                f.write(file_content)
            
            log.debug(f"Backed up {remote_path} to {local_backup_path}")
        except Exception as e:
            log.error(f"Failed to backup {remote_path}: {str(e)}")

    def write_file(self, remote_path, content):
        try:
            file_id = self.smb_conn.createFile(self.tree_id, remote_path)
            self.smb_conn.writeFile(self.tree_id, file_id, content)
            self.smb_conn.closeFile(self.tree_id, file_id)
            log.info(f"Updated file: {remote_path}")
        except Exception as e:
            log.error(f"Failed to write file {remote_path}: {str(e)}")
            raise

    def list_users(self):
        users = []
        try:
            files = self.smb_conn.listPath("C$", "Users\\*")
            for file in files:
                if file.is_directory() and file.get_longname() not in ['.', '..']:
                    users.append(file.get_longname())
            return users
        except Exception as e:
            log.error(f"Failed to list users: {str(e)}")
            return []

    def read_file(self, remote_path):
        try:
            file_id = self.smb_conn.openFile(self.tree_id, remote_path, desiredAccess=FILE_READ_DATA)
            file_content = self.smb_conn.readFile(self.tree_id, file_id)
            self.smb_conn.closeFile(self.tree_id, file_id)
            return file_content
        except Exception as e:
            log.error(f"Failed to read file {remote_path}: {str(e)}")
            raise

def create_smb_connection(target, username, password, domain):
    smb_ops = SMBOperations(target, username, password, domain)
    smb_ops.connect()
    return smb_ops