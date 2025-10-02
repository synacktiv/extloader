from impacket.dcerpc.v5 import transport, lsat, lsad
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smbconnection import SMBConnection
from .utils import log

def get_user_sids(target, username, auth_value, domain, users, auth_type="password", existing_smb_conn=None):
    """Get SIDs for the specified users using the same authentication method as the main connection."""
    # List of system accounts to skip
    system_accounts = {
        'All Users', 'Default', 'Default User', 'Public', 
        'desktop.ini', 'Public Downloads'
    }
    
    # Filter out system accounts
    filtered_users = [user for user in users if user not in system_accounts]
    
    try:
        # Use existing SMB connection if provided
        if existing_smb_conn:
            smb_conn = existing_smb_conn
        else:
            smb_conn = SMBConnection(target, target, sess_port=445)
            # Use the same auth method as the main connection
            if auth_type == "password":
                smb_conn.login(username, auth_value, domain)
            elif auth_type == "hash":
                if ':' in auth_value:
                    lm_hash, nt_hash = auth_value.split(':')
                else:
                    lm_hash = 'aad3b435b51404eeaad3b435b51404ee'
                    nt_hash = auth_value
                smb_conn.login(username, '', domain, lmhash=lm_hash, nthash=nt_hash)
        
        log.info(f"Retrieving SIDs for users on {target}")
        
        stringbinding = r'ncacn_np:%s[\pipe\lsarpc]' % target
        log.debug(f"Stringbinding: {stringbinding}")
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(445)

        # Set credentials based on auth type
        if auth_type == "password":
            rpctransport.set_credentials(username, auth_value, domain)
        elif auth_type == "hash":
            if ':' in auth_value:
                lm_hash, nt_hash = auth_value.split(':')
            else:
                lm_hash = 'aad3b435b51404eeaad3b435b51404ee'
                nt_hash = auth_value
            rpctransport.set_credentials(username, '', domain, lm_hash, nt_hash)

        try:
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(lsat.MSRPC_UUID_LSAT)

            resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
            policy_handle = resp['PolicyHandle']

            resp = lsad.hLsarQueryInformationPolicy2(dce, policy_handle, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)
            domain_sid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()

            log.info(f"Domain SID is: {domain_sid}")

            user_sids = {}
            for user in filtered_users:
                try:
                    resp = lsat.hLsarLookupNames2(dce, policy_handle, (user,), lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
                    rid = resp['TranslatedSids']['Sids'][0]['RelativeId']
                    user_sid = f"{domain_sid}-{rid}"
                    user_sids[user] = user_sid
                    log.info(f"SID for {user}: {user_sid}")
                except DCERPCException as e:
                    log.warning(f"Error retrieving SID for {user}: {str(e)}")

            dce.disconnect()
            return user_sids

        except Exception as e:
            log.error(f"Error in get_user_sids RPC operations: {str(e)}")
            return {}

    except Exception as e:
        log.error(f"Error in get_user_sids: {str(e)}")
        return {}