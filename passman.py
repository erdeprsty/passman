from hashlib import pbkdf2_hmac, sha256
import base64
import hmac
import sys

if len(sys.argv) < 2:
    print('Master key argument is required')
    exit()
if len(sys.argv) < 3:
    print('Platform credential argument is required')
    exit()
if not sys.argv[1]:
    print('Invalid master key')
    exit()
if not sys.argv[2]:
    print('Invalid platform credential')
    exit()

master_key = sys.argv[1]
credential = sys.argv[2].split('@')

PLATFORMS = {'google': {
    'ardihariprasetiyooo': 'rLwJxOcYkzSW9/0tciae693WFQePUoMcgvtECNrhsdc='}}
VALID_SECRET_DIGEST = 'FFDw3BDd0cjQggMw2mDjsyJyBpOoyYzSsG1/QVrG5bo='
master_key_digest = base64.b64encode(hmac.new(bytes(
    master_key, encoding='utf-8'), bytes(master_key, encoding='utf-8'), sha256).digest()).decode('utf-8')
if master_key_digest != VALID_SECRET_DIGEST:
    print('Invalid master key')
    exit()

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
