from click.exceptions import ClickException
import typer
from wgeasywall.vars import *
from pathlib import Path

app = typer.Typer()


@app.command()
def database():
    """
    View MongoDB Configuration
    """
    mongoConfigPath = get_mongo_configuration_location()

    if (not Path(mongoConfigPath).is_file()):
        typer.echo("ERROR: The cli.yaml file can't be found please use CLI to generate it!",err=True)
        raise typer.Exit(code=1)
    
    typer.echo("Open CLI Configuration File in {0}".format(mongoConfigPath))
    typer.echo("\n")
    with open(mongoConfigPath) as mongo:
    # Here f is the file-like object
        read_data = mongo.read()
        typer.echo(read_data)