from click.termui import confirm
import typer
import yaml
from pathlib import Path
from wgeasywall.vars import *
import os

app = typer.Typer()

@app.command()
def database(
    mongo_address: str = typer.Option(...,"--mongodb-address",envvar="MONGODB_ADDRESS",help="The address of MongoDB"),
    mongo_user: str = typer.Option(...,"--mongodb-user",envvar="MONGODB_USER",help="The username that access database"),
    mongo_password: str = typer.Option(...,"--mongodb-password",help="The password of user who access the database"),
):
    """
    Generate MongoDB configuration file that need to access database in the ~/.wgeasywall location

    ------------
    
    Example:

    wgeasywall config generate database --mongodb-address 127.0.0.1 --mongodb-user wgeasywall --mongodb-password wgeasywall
    """
    config = {}
    config["MongoDB"] = {}

    CLI_Config_Location = get_wgeasywall_config_location()
    configFileLocation = get_mongo_configuration_location()
    if Path(configFileLocation).is_file():
        overwrite = typer.confirm("The MongoDB configuration exists, Do you want to generate it again?")
        if not overwrite:
            typer.echo("Not Generating New Configuration File")
            raise typer.Abort()
    typer.echo("Generate New Config File")
    config["MongoDB"]["mongo_address"] = mongo_address
    config["MongoDB"]["mongo_user"] = mongo_user
    config["MongoDB"]["mongo_password"] = mongo_password

    if not os.path.exists(CLI_Config_Location):
        os.makedirs(CLI_Config_Location)
    try:
        with open(configFileLocation,'w') as file:
            configFile = yaml.dump(config,file)
    except Exception as e:
        typer.echo(e,err=True)
        raise typer.Abort()

