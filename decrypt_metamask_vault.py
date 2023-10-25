from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, keccak
import binascii, os, re
import hashlib, base64, json, argparse, sys, getpass

desc = """Metamask Vault Decrypter:
    Take the encrypted Vault file(s) and password (or password list) and attempt to decrypt the wallet(s)
    Obtain the Vault file from the Browser Extension in following location:

    1) Firefox
      moz-extension://UUID/home.html
      inspect element ... chrome.storage.local.get('data', result=> {var vault=result.data.KeyringController.vault; console.log(vault)})

    2) Chrome
      %LocalAppData%\\Google\\Chrome\\UserData\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn
      Ideally parse the LevelDB (eg LevelDBDumper) and output the json
      Alternatively, search all *.ldb files for "vault" and extract the JSON

    3) Mobile
      /private/var/mobile/[Application]/persistStore/persist-root

    Please note, Metamask enforces a minimum password length of 8 characters

    See the following link for further details:
    https://metamask.zendesk.com/hc/en-us/articles/360018766351-How-to-use-the-Vault-Decryptor-with-the-MetaMask-Vault-Data

    Further work:
    - parse vaults pasted in the command line
    - parse levelDB files
    
    ~dcmattb
"""

def robust_find_vault():
    pattern = r'\{(?:[^{}]*\\"?(?:data|cipher)\\"?[^{}]*\\"?salt\\"?[^{}]*\\"?iv\\"?|[^{}]*\\"?salt\\"?[^{}]*\\"?iv\\"?[^{}]*\\"?(?:data|cipher)\\"?|[^{}]*\\"?iv\\"?[^{}]*\\"?salt\\"?[^{}]*\\"?(?:data|cipher)\\"?|[^{}]*\\"?(?:data|cipher)\\"?[^{}]*\\"?iv\\"?[^{}]*\\"?salt\\"?)[^{}]*\}'
    #TODO

def unescape_json(snippet):
    previous_snippet = None
    while snippet != previous_snippet:
        try:
            return json.loads(snippet)
        except json.JSONDecodeError:
            previous_snippet = snippet
            snippet = snippet.encode().decode('unicode_escape')
            #unescaped_snippet = new_snippet.replace('\\\\', '\\').replace('\\"', '"')
    try:
        return json.loads(snippet)
    except json.JSONDecodeError:
        return None

def gpt_find_vault(text, file=""):
    extracted_values_list = []
    # Regular expression to identify possible JSON objects within curly braces
    snippet_pattern = r'\{[^{}]+\}'
    snippets = re.findall(snippet_pattern, text)
    for snippet in snippets:
        snippet_dict = unescape_json(snippet)
        if snippet_dict:
            def search_dict(d):
                for key, value in d.items():
                    if isinstance(value, dict):
                        search_dict(value)  # Recursion for nested dictionaries
                    elif key in ['data', 'cipher', 'salt', 'iv']:
                        if 'data' in d or 'cipher' in d:
                            if 'salt' in d and 'iv' in d:
                                extracted_values_list.append({
                                    'data': d.get('data', d.get('cipher')),
                                    'salt': d['salt'],
                                    'iv': d['iv'],
                                    'type': 'mobile' if 'cipher' in d else 'extension',
                                    'filename': file,   #Comment this to eliminate duplicates in other files
                                })
            search_dict(snippet_dict)
    return extracted_values_list


def check_valid_vault(file, size_limit=104857600):  #Default 100MB size limit
    keyword_patterns = [re.compile(r'iv'), re.compile(r'salt'), re.compile(r'data|cipher')]
    if os.path.getsize(file) > size_limit:
        print(f" Skipping (too large): {file_path}")
        return []
    try:
        with open(file, 'r', encoding='utf-8') as f:
            content = f.read()
        if all(pattern.search(content) for pattern in keyword_patterns):
            return [file]
        else:
            print(f" Skipping (vault not found): {file}")
    except:
        #Parse leveldbs here? TODO
        print(f" Skipping (cannot read): {file}")
    return []

def get_vaults(text):
    ''' Return a list of valid vault files'''
    if not text:
        exit("Please specify the vault file / directory!")
    if not os.path.exists(text):
        #get/check in command line? TODO
        exit("vault file / directory not found!")
    if os.path.isfile(text):
        return check_valid_vault(text)
    vault_files = []
    for root, _, files in os.walk(text):
        for file in files:
            file_path = os.path.join(root, file)
            vault_files += check_valid_vault(file_path)
    return vault_files

def get_passwords(text, unicode=False):
    ''' Metamask enforces an 8 character minimum (mobile and extension)'''
    if not text:
        password_lines = [getpass.getpass('Type the password or path to password list:')]
    else:
        password_lines = [text]
    if os.path.exists(text) and os.path.isfile(text):
        with open(text, 'r') as f:
            password_lines = f.readlines()
    passwords = []
    skipped = 0
    for p in password_lines:
        pw = p.strip()
        if len(pw)<8:
            skipped += 1
            continue
        passwords += [pw]
    print(f" {len(passwords)} password loaded")
    if skipped>0:
        print(f" {skipped} passwords skipped (too short)")
    return passwords

def remove_duplicate_dicts(dict_list):
    unique_dict_strings = set()
    unique_dicts = []
    for d in dict_list:
        json_str = json.dumps(d, sort_keys=True)
        if json_str not in unique_dict_strings:
            unique_dict_strings.add(json_str)
            unique_dicts.append(d)
    return unique_dicts

def vault_decrypt_mobile(vault, passwords, mask=False):
    tot = len(passwords)
    ctext = base64.b64decode(vault["data"])
    salt = vault["salt"].encode()
    iv = binascii.unhexlify(vault["iv"])
    for i,p in enumerate(passwords):
        key = hashlib.pbkdf2_hmac(
            'sha512',
            p.encode('utf-8'), # Convert the password to bytes
            salt,
            5000,
            32  #key length - 16/24/32/None
        )
        aesCipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = aesCipher.decrypt(ctext)
        #show_info(ctext, key, iv, salt)
        if check_plaintext(plaintext, mask):
            print()
            print(f"Password:   {p}")
            break
        print(f"  {(i+1):<3}/{tot} '{vault['filename']}'     ", end='\r')
    print(" Failed")

def vault_decrypt_extension(vault, passwords, mask=False):
    tot = len(passwords)
    ctext = base64.b64decode(vault["data"])
    salt = base64.b64decode(vault["salt"])
    try:
        iv = binascii.a2b_hex(vault["iv"])
    except:
        iv = base64.b64decode(vault["iv"])
    for i,p in enumerate(passwords):
        key = hashlib.pbkdf2_hmac(
            'sha256',
            p.encode('utf-8'), # Convert the password to bytes
            salt,
            10000,
            32
        )
        aesCipher = AES.new(key, AES.MODE_GCM, iv)
        plaintext = aesCipher.decrypt(ctext)
        #show_info(ctext, key, iv, salt)
        if check_plaintext(plaintext, mask):
            print(f"Password:   {p}")
            break
        print(f"  {(i+1):<3}/{tot} '{vault['filename']}'     ", end='\r')
    print()

def check_plaintext(pt, mask=False):
    try:
        chk = pt[:32].decode("utf-8")
    except UnicodeDecodeError:
        #Incorrect password
        return False
    plaintext = pt.decode("utf-8", "ignore")
    try:
        d=json.JSONDecoder()
        decrypted_vault,extra = d.raw_decode(plaintext)
        mn = decrypted_vault[0]["data"]["mnemonic"]
        try:    #character based mnemonic:
            mn = ''.join(map(chr, mn))
        except: #Old text based mnemonic
            mn = mn
        print()
        if mask:
            mn2 = mn.split(' ')
            print(f"Mnemonic:   {' '.join(mn2[:3])}...({len(mn2)} words)")
        else:
            print(f"Mnemonic:   {mn}")
        return True
    except json.JSONDecodeError:
        print("\nError parsing decrypted data")
        print(f"Plain:      {plaintext}")
    return False

def show_info(cipher, key, iv, salt):
    print(f"Ciphertext: {binascii.b2a_hex(cipher).decode('utf-8')}")
    print(f"Key:        {binascii.b2a_hex(key).decode('utf-8')}")
    print(f"iv:         {binascii.b2a_hex(iv).decode('utf-8')}")
    print(f"salt:       {binascii.b2a_hex(salt).decode('utf-8')}")

def main():
    parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.RawTextHelpFormatter,
    usage='\tpython %(prog)s vault.js [-p passwordlist]' )
    parser.add_argument('vaultfile', nargs='?', metavar='vault', help='vault file or "persist-root" (must include: {"data":"....", "iv":"....", "salt":"...."} )')
    parser.add_argument('--passwordlist', '-p', nargs='?', help='Password list or single password (if not given, you will be prompted for the password)', dest='password')
    parser.add_argument('--mask', '-x', help='Just test the password, only reveal the first 3 seeds', action='store_true', dest='mask')
    parser.add_argument('--mobile', '-m', help='Force mobile version (app)', action='store_true', dest='mobile')
    parser.add_argument('--extension', '-e', help='Force desktop extension version (browser)', action='store_true', dest='extension')
    args = parser.parse_args()

    vaultfiles = get_vaults(args.vaultfile)
    passwords = get_passwords(args.password)

    vaults = []
    for vfile in vaultfiles:
        with open(vfile, 'r') as f:
            data = f.read()
            vault = gpt_find_vault(data, vfile)
            if len(vault)==0:
                print(f"No vault data in {vfile}")
            else:
                pass
                #print(json.dumps(vault, indent=2))
        vaults += vault
    vaults = remove_duplicate_dicts(vaults)
    print(f"Checking {len(vaults)} vaults with {len(passwords)} passwords...")

    for i,v in enumerate(vaults):
        if args.mobile or v["type"]=="mobile":
            vault_decrypt_mobile(v, passwords, args.mask)
        if args.extension or v["type"]=="extension":
            vault_decrypt_extension(v, passwords, args.mask)

if __name__ == "__main__":
    main()
