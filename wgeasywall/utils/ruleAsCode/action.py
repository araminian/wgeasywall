import yaml
import re
from wgeasywall.utils.ruleAsCode.function import catagorizeArgs, ifMandatoryArgsExists,parseArgument,getVariable
from wgeasywall.utils.mongo.gridfsmongo import findAbstract

def getActionName(action):

    return action.split('(')[0]

def getActionBody(action):

    actionBody = re.findall(r'\((.+?)\)',action)
    if (len(actionBody) == 0):
        actionBody = None
    else:
        actionBody = actionBody[0]
    
    return actionBody

def getActionArguments(action):
    actionBody = getActionBody(action)
    if ( actionBody != None):
        return actionBody.split(':')
    else:
        return None
    
def getActionArgumentsName(args):
    
    argumentsName = []
    for arg in args:
      argName = arg.split('=')[0]
      argumentsName.append(argName)
    return argumentsName


def generateAction(action,actionDefinition):

    argOption = []

    actionDefiArgument = actionDefinition['Action']['Body']['Arguments']
    actionDefiVars = actionDefinition['Action']['Body']['Variables']
    actionBodyMain = actionDefinition['Action']['Body']['Main']

    # Sort arguments to Optional and Mandatory
    mandatoryArguments, optionalArguments = catagorizeArgs(actionDefiArgument)
    mandatoryArgumentsName = list(mandatoryArguments.keys())
    optionalArgumensName = list(optionalArguments.keys())

    actionArguments = getActionArguments(action)

    if ((len(mandatoryArgumentsName) != 0 or len(optionalArgumensName) !=0) and actionArguments == None):
        return {"ErrorCode":"300","ErrorMsg":"The action arguments are defined in the definition but no arguments are definied in the action"}
    
    if (actionArguments == None):
        actionArguments = []
    
    actionArgumentsNameList= getActionArgumentsName(actionArguments)
    checkAllMandatoryArgs = ifMandatoryArgsExists(actionArgumentsNameList,mandatoryArgumentsName)

    if( not checkAllMandatoryArgs):
      return {"ErrorCode":"300","ErrorMsg":"All mandatory arguments are not defined in the function"}
    

    for arg in actionArguments:

        parsedArg = parseArgument(arg)
      
        argName = parsedArg[0]
        argValue = parsedArg[1]
        
        argumentDefiniton = actionDefiArgument[argName]['Definition']
        variableName = getVariable(argumentDefiniton)

        if (variableName not in actionDefiVars):
          return {"ErrorCode":"300","ErrorMsg":"The variable '{0}' which is used in the Argument definition doesn't exist on the Variable definition.".format(variableName)}

        if (argValue == None and 'Default' not in actionDefiVars[variableName]):
          return {"ErrorCode":"300","ErrorMsg":"Argument '{0}' has no defined values in action and default in action definition.".format(argName)}

        variableDefinition = actionDefiVars[variableName]

        if (argValue == None):
          argValue = variableDefinition['Default'].split(',')
      
        argValue = ','.join(argValue)
        generatedArgument = argumentDefiniton.replace("<{0}>".format(variableName), argValue)

        argOption.append(generatedArgument)
    argOption.insert(0,actionBodyMain)
    return argOption

def extractActionDefinition(action,version):

    query = {'filename':'{0}.yaml'.format(action)}
    files = findAbstract('RaaC','action',query=query)

    if(len(files) == 0):
        return {"ErrorCode":"301","ErrorMsg":"The Action '{0}' doesn't exist on the database.".format(action)}


    if (version == '@latest'):
        return yaml.safe_load(files[-1].read().decode())

    ifActionExist = False
    desireFile = None
    for file in files:
        if(file.uniqueName == version):
            ifActionExist = True
            desireFile = file
    
    if (not ifActionExist):
        return {"ErrorCode":"301","ErrorMsg":"The Action '{0}' with the version of '{1}' doesn't exist on the database.".format(action,version)}
    
    return yaml.safe_load(desireFile.read().decode())
