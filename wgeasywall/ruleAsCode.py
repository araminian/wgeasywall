import typer
from pathlib import Path
from os import remove
from wgeasywall.utils.general.filedir import create_temporary_copy
from wgeasywall.utils.mongo.gridfsmongo import upload, findAbstract,delete
from coolname import generate_slug
from wgeasywall.utils.general.configParser import get_configuration
from typing import Optional

app = typer.Typer()

@app.command()
def import_function(
    funcFile: Path = typer.Option(...,"--function-file",help="The function definition file"),
    version: str = typer.Option(...,"--version",help="The function version"),
    force : Optional[bool] = typer.Option(False,"--force",help="Force adding and overwriting rule even if the rule exists"),
):  

    if not funcFile.is_file():
        typer.echo("ERROR: Function Definition file can't be found!",err=True)
        raise typer.Exit(code=1)
    
    funcDefiDict = get_configuration(funcFile)

    if (type(dict) and 'ErrorCode' in funcDefiDict):

        typer.echo("ERORR: Can't read Function Definition file.  {0}".format(funcDefiDict['ErrorMsg']))
        raise typer.Exit(code=1)

    functionName = funcDefiDict['Func']['Name']


    query = {'filename':'{0}.yaml'.format(functionName)}
    files = findAbstract('RaaC','function',query=query)
    
    ifRuleExist = False
    fileID2Delete = None
    for file in files:
        if(file.uniqueName == version):
            ifRuleExist = True
            fileID2Delete = file._id
    
    if (ifRuleExist):
        doOverwrite = False
        confirmOverwrite = False
        if(force):
            doOverwrite = True
        else:
            confirmOverwrite = typer.confirm("The function '{0}' with the version '{1}' exists. do you want to overwrite it?".format(functionName,version))
        
        if (confirmOverwrite):
            doOverwrite = True
        
        if (not doOverwrite):
            typer.echo("Overwriting abort.")
            raise typer.Exit(code=0)
        
        deleteResult = delete(db='RaaC',fs='function',fileID=fileID2Delete)
        if (deleteResult != True):
            typer.echo('ERROR: Unable to overwrite.')
            raise typer.Exit(code=1)

    funcTempPath = create_temporary_copy(path=funcFile,networkName="{0}.yaml".format(functionName))
    
    upload(db='RaaC',fs='function',filePath=funcTempPath,uniqueName=version)
    remove(funcTempPath)
    typer.echo("The provided Function definition '{0}' with the version '{1}' is added to the database.".format(functionName,version))


