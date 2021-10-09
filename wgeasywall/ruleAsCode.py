import typer
from pathlib import Path
from os import remove
from wgeasywall.utils.general.filedir import create_temporary_copy
from wgeasywall.utils.mongo.gridfsmongo import upload, findAbstract,delete
from coolname import generate_slug
from wgeasywall.utils.general.configParser import get_configuration
from typing import Optional
from wgeasywall.utils.ruleAsCode.generate import createRules

app = typer.Typer()

@app.command()
def import_function(
    funcFile: Path = typer.Option(...,"--function-file",help="The function definition file"),
    force : Optional[bool] = typer.Option(False,"--force",help="Force adding and overwriting function even if the function exists"),
):  

    if not funcFile.is_file():
        typer.echo("ERROR: Function Definition file can't be found!",err=True)
        raise typer.Exit(code=1)
    
    funcDefiDict = get_configuration(funcFile)

    if (type(dict) and 'ErrorCode' in funcDefiDict):

        typer.echo("ERORR: Can't read Function Definition file.  {0}".format(funcDefiDict['ErrorMsg']))
        raise typer.Exit(code=1)

    functionName = funcDefiDict['Func']['Name']
    version = funcDefiDict['Func']['Version']

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


@app.command()
def import_action(
    actionFile: Path = typer.Option(...,"--action-file",help="The action definition file"),
    force : Optional[bool] = typer.Option(False,"--force",help="Force adding and overwriting action even if the action exists"),
):  

    if not actionFile.is_file():
        typer.echo("ERROR: Action Definition file can't be found!",err=True)
        raise typer.Exit(code=1)
    
    funcDefiDict = get_configuration(actionFile)

    if (type(dict) and 'ErrorCode' in funcDefiDict):

        typer.echo("ERORR: Can't read Action Definition file.  {0}".format(funcDefiDict['ErrorMsg']))
        raise typer.Exit(code=1)

    actionName = funcDefiDict['Action']['Name']
    version = funcDefiDict['Action']['Version']

    query = {'filename':'{0}.yaml'.format(actionName)}
    files = findAbstract('RaaC','action',query=query)
    
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
            confirmOverwrite = typer.confirm("The function '{0}' with the version '{1}' exists. do you want to overwrite it?".format(actionName,version))
        
        if (confirmOverwrite):
            doOverwrite = True
        
        if (not doOverwrite):
            typer.echo("Overwriting abort.")
            raise typer.Exit(code=0)
        
        deleteResult = delete(db='RaaC',fs='action',fileID=fileID2Delete)
        if (deleteResult != True):
            typer.echo('ERROR: Unable to overwrite.')
            raise typer.Exit(code=1)

    funcTempPath = create_temporary_copy(path=actionFile,networkName="{0}.yaml".format(actionName))
    
    upload(db='RaaC',fs='action',filePath=funcTempPath,uniqueName=version)
    remove(funcTempPath)
    typer.echo("The provided action definition '{0}' with the version '{1}' is added to the database.".format(actionName,version))

@app.command()
def generate_rule(
    rule : str = typer.Option(...,"--rule",help="The rule should be parsed"),
    actionVersion: str = typer.Option("@latest","--action-version",help="The version of Action which"),
    functionVersion: str = typer.Option("@latest","--function-version",help="The version of Function")
):

    ruleEnd = createRules(
        function=rule,
        actionVersion=actionVersion,
        functionVersion=functionVersion
    )

    if (type(ruleEnd) == dict):
        typer.echo("ERROR: {0}".format(ruleEnd['ErrorMsg']))
        raise typer.Exit(code=1)
    
    for rule in ruleEnd:
        typer.echo(' '.join(rule))