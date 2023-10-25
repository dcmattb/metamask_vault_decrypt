 ## Metamask Vault Decrypt
 
 ### 1. Obtaining the vault
 
 Take the encrypted Vault file(s) and password (or password list) and attempt to decrypt the wallet(s)
 
Obtain the Vault file from the Browser Extension in following location:

1. Firefox
   
	`moz-extension://UUID/home.html`
	(right click) inspect element
	```
	chrome.storage.local.get('data', result=> {var vault=result.data.KeyringController.vault; console.log(vault)})
	```
3. Chrome
   
	In an explorer window:
	```
	%LocalAppData%\\Google\\Chrome\\UserData\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn
	```
	Ideally parse the LevelDB (eg LevelDBDumper) and output the json
Alternatively, search all *.ldb files for "vault" and extract the json

3) Mobile
      ```
      /private/var/mobile/[Application]/persistStore/persist-root
      ```

Please note, Metamask enforces a minimum password length of 8 characters, shorter passwords will be ignored by the script.

See the following link for further details on extracting the vault:

https://metamask.zendesk.com/hc/en-us/articles/360018766351-How-to-use-the-Vault-Decryptor-with-the-MetaMask-Vault-Data

### 2. Running the script

```python
python decrypt_metamask_vault.py -p passwordlist vaultfile
```

### 3. Further work
- parse levelDB
- parse vaults pasted in the command line
