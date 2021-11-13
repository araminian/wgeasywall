import typer
from pathlib import Path
from os import remove
from wgeasywall.utils.general.filedir import create_temporary_copy
from wgeasywall.utils.mongo.gridfsmongo import upload, findAbstract,delete
from coolname import generate_slug
from wgeasywall.utils.general.configParser import get_configuration
from typing import Optional
from wgeasywall.utils.ruleAsCode.generate import createRules, migrateToNFT

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
    actionVersion: str = typer.Option("@latest","--action-version",help="The version of Action"),
    functionVersion: str = typer.Option("@latest","--function-version",help="The version of Function"),
    nft: Optional[bool] = typer.Option(False,"--nft",help="Generate NFT syntax")
):

    ruleEnd = createRules(
        function=rule,
        actionVersion=actionVersion,
        functionVersion=functionVersion
    )

    if (type(ruleEnd) == dict):
        typer.echo("ERROR: {0}".format(ruleEnd['ErrorMsg']))
        raise typer.Exit(code=1)
    # ruleEnd is List of List
    for rule in ruleEnd:
        rule2show = ' '.join(rule)
        if (not nft):
            typer.echo(rule2show)
        else:
            nftRule = migrateToNFT(rule2show)
            nftRuleComponents = nftRule.split(" ")
            desiredIndex = nftRuleComponents.index("FORWARD")
            typer.echo(' '.join(nftRuleComponents[desiredIndex+1:]))

@app.command()
def delete_function(
    function: str = typer.Option(None,"--function",help="The function name"),
    version: str = typer.Option(None,"--version",help="The version of function. Use @latest to get the latest")
):

    query = {'filename':'{0}.yaml'.format(function)}
    files = findAbstract('RaaC','function',query=query)

    if(len(files) == 0):
        typer.echo("ERROR: The function '{0}' doesn't exist on the database.".format(function))
        raise typer.Exit(code=1)
    
    if (version == '@latest'):
        deleteResult = delete('RaaC','function',files[-1]._id)
        if(type(deleteResult) == dict and 'ErrorCode' in deleteResult):
            typer.echo("ERROR: Function can't be deleted : {0}".format(deleteResult['ErrorMsg']))
            raise typer.Exit(code=1)
        typer.echo("The latest version of function '{0}' is deleted".format(function))
        raise typer.Exit(code=0)

    for file in files:
        if(version != None and file.uniqueName != version):
            continue
        deleteResult = delete('RaaC','function',file._id)
        if(type(deleteResult) == dict and 'ErrorCode' in deleteResult):
            typer.echo("ERROR: Function can't be deleted : {0}".format(deleteResult['ErrorMsg']))
            raise typer.Exit(code=1)
        typer.echo("The version '{1}' of function '{0}' is deleted.".format(function,file.uniqueName))
        raise typer.Exit(code=0)
    typer.echo("ERROR: The '{0}' version of function '{1}' doesn't exist to be deleted".format(version,function))
    raise typer.Exit(code=1)

@app.command()
def delete_action(
    action: str = typer.Option(None,"--action",help="The action name"),
    version: str = typer.Option(None,"--version",help="The version of action. Use @latest to get the latest")
):

    query = {'filename':'{0}.yaml'.format(action)}
    files = findAbstract('RaaC','action',query=query)

    if(len(files) == 0):
        typer.echo("ERROR: The action '{0}' doesn't exist on the database.".format(action))
        raise typer.Exit(code=1)
    
    if (version == '@latest'):
        deleteResult = delete('RaaC','action',files[-1]._id)
        if(type(deleteResult) == dict and 'ErrorCode' in deleteResult):
            typer.echo("ERROR: Action can't be deleted : {0}".format(deleteResult['ErrorMsg']))
            raise typer.Exit(code=1)
        typer.echo("The latest version of action '{0}' is deleted".format(action))
        raise typer.Exit(code=0)

    for file in files:
        if(version != None and file.uniqueName != version):
            continue
        deleteResult = delete('RaaC','action',file._id)
        if(type(deleteResult) == dict and 'ErrorCode' in deleteResult):
            typer.echo("ERROR: Action can't be deleted : {0}".format(deleteResult['ErrorMsg']))
            raise typer.Exit(code=1)
        typer.echo("The version '{1}' of action '{0}' is deleted.".format(action,file.uniqueName))
        raise typer.Exit(code=0)
    typer.echo("ERROR: The '{0}' version of action '{1}' doesn't exist to be deleted".format(version,action))
    raise typer.Exit(code=1)