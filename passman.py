from hashlib import pbkdf2_hmac, sha256
import base64
import hmac

PLATFORMS = {'google': {
    'ardihariprasetiyooo': 'rLwJxOcYkzSW9/0tciae693WFQePUoMcgvtECNrhsdc='}}
SERCRET_KEY = '4mefIs6EkILQCACfojqfru2QczGxPlc4oOytQoPivG0='
master_key = input('Master key: ')
master_key_digest = base64.b64encode(hmac.new(bytes(
    master_key, encoding='utf-8'), b'masterkey', sha256).digest()).decode('utf-8')
if master_key_digest != SERCRET_KEY:
    print('Invalid master key')
    exit()

credential = input('platform@account: ').split('@')
credential_platform = credential[0]
credential_account = len(credential) > 1 and credential[1] or None
if credential_platform not in PLATFORMS.keys():
    print('Unable to retrive key: unknown platform')
    exit()
selected_credential = PLATFORMS[credential_platform]
if isinstance(selected_credential, dict):
    if credential_account:
        if not credential_account in PLATFORMS[credential_platform].keys():
            print(
                f'Unable to retrive key: account ({credential_account}) was not registered on selected platform ({credential_platform})')
            exit()
        selected_credential = PLATFORMS[credential_platform][credential_account]
    else:
        selected_credential = list(
            PLATFORMS[credential_platform].items())[0][1]
key = pbkdf2_hmac('sha256', bytes(master_key, encoding='utf-8'),
                  base64.b64decode(selected_credential), 600_000, 32)
print(f'Key: {base64.b64encode(key).decode("utf-8")}')
