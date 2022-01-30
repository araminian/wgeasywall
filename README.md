
## What is WGEasywall
[WGEasywall](https://github.com/araminian/wgeasywall) is a CLI to manage Wireguard networks and IPTables rules using GraphML


## How to Install and Configure WGEasywall

WGEasywall needs python version 3.8 or above. It can be installed using following command:

```bash
pip install wgeasywall
```

WGEasywall needs MongoDB database to start working. We should tell it how to access the database using following command:

```bash
wgeasywall config generate database --mongodb-address [MongoDB Address] --mongodb-user [USER] --mongodb-password [PASSWORD]
```

> **_NOTE:_**  WGEasywall access database using default port 27017 and it can not be changed


WGEasywall IPTables rule generator needs `Rule as a Code` `Actions and Function` manifest file. These manifest files should be imported to the WGEasywall. These manifest files are located in `RaaCManifest` folder.
We can import these files using following commands:

```bash
# import general function
wgeasywall RaaC import-function --function-file General.yaml

# import DROP action
wgeasywall RaaC import-action --action-file DROP.yaml

# import ACCEPT action
wgeasywall RaaC import-action --action-file ACCEPT.yaml

# import LOG action
wgeasywall RaaC import-action --action-file LOG.yaml
```

> **_NOTE:_**  These manifest can be changed but they should be compatible with WGEasywall 

Now wgeasywall is ready for managing WireGuard networks and IPTables rules.
