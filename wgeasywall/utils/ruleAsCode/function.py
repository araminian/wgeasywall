import yaml
import re
from wgeasywall.utils.mongo.gridfsmongo import findAbstract

def getFunctionArgumentsName(args):
    
    argumentsName = []
    for arg in args:
      argName = arg.split('=')[0]
      argumentsName.append(argName)
    return argumentsName

def ifMandatoryArgsExists(functionArgs,mandatoryArgs):

  for mandatoryArg in mandatoryArgs:
    if (mandatoryArg not in functionArgs):
      return False
  return True

def parseArgument(arg):
    argName = arg.split('=')[0]
    if (len(arg.split('=')) > 1):
        args = (arg.split('=')[1]).split(',')
    else:
        args = None
    return (argName,args)

def catagorizeArgs(args):

    optional = {}
    mandatory = {}

    for argName,argValue in args.items():
        
        if ('Optional' not in argValue or argValue['Optional']):
            optional [argName] = argValue['Definition']
        elif(not argValue['Optional']):
            mandatory [argName] = argValue['Definition']
    
    return (mandatory,optional)

def getFunction(function):

    return function.split('::')[0]

def getFunctionName(function):

    return getFunction(function).split('(')[0]

def getFunctionBody(function):

    functionBody = re.findall(r'\((.+?)\)',getFunction(function))
    if (len(functionBody) == 0):
        functionBody = None
    else:
        functionBody = functionBody[0]
    
    return functionBody

def getFunctionArguments(function):
    functionBody = getFunctionBody(function)
    if ( functionBody != None):
        return functionBody.split(':')
    else:
        return None

def getFunctionAction(function):
  if (len(function.split('::')) > 1):
      Action = function.split('::')[1]
  else:
      Action = None
  
  return Action
    
def getVariable(argument):
    variable = re.findall(r'\<(.+?)\>',argument)[0]
    return variable

def generateRule(function,functionDefinition):

    argOption = []

    functionDefiArguments = functionDefinition['Func']['Body']['Arguments']
    functionDefiVars = functionDefinition['Func']['Body']['Variables']
    functionDefiBodyMain = functionDefinition['Func']['Body']['Main']

    # Sort arguments to Optional and Mandatory
    mandatoryArguments, optionalArguments = catagorizeArgs(functionDefiArguments)
    mandatoryArgumentsName = list(mandatoryArguments.keys())
    optionalArgumensName = list(optionalArguments.keys())

    functionArguments = getFunctionArguments(function)

    if ((len(mandatoryArgumentsName) != 0 or len(optionalArgumensName) !=0) and functionArguments == None):
        return {"ErrorCode":"300","ErrorMsg":" The function arguments are defined in the definition but no arguments are definied in the function."}

    if (functionArguments == None):
        functionArguments = []

    functionArgumentsNameList= getFunctionArgumentsName(functionArguments)

    checkAllMandatoryArgs = ifMandatoryArgsExists(functionArgumentsNameList,mandatoryArgumentsName)

    if( not checkAllMandatoryArgs):
      return {"ErrorCode":"300","ErrorMsg":" All mandatory arguments are not defined in the function."}

    
    for arg in functionArguments:
      parsedArg = parseArgument(arg)
      
      argName = parsedArg[0]
      argValue = parsedArg[1]


      argumentDefiniton = functionDefiArguments[argName]['Definition']
      variableName = getVariable(argumentDefiniton)
      if (variableName not in functionDefiVars):
          return {"ErrorCode":"300","ErrorMsg":"The variable '{0}' which is used in the Argument definition doesn't exist on the Variable definition.".format(variableName)}

      variableDefinition = functionDefiVars[variableName]

      if (argValue == None and 'Default' not in functionDefiVars[variableName]):
        return {"ErrorCode":"300","ErrorMsg":" Argument '{0}' has no defined values in function and default in function definition.".format(argName)}

      
      if (argValue == None):
        argValue = variableDefinition['Default'].split(',')
      
      argValue = ','.join(argValue)
      generatedArgument = argumentDefiniton.replace("<{0}>".format(variableName), argValue)

      argOption.append(generatedArgument)

    argOption.insert(0,functionDefiBodyMain)
    
    return argOption

def extractFunctionDefinition(function,version):

    query = {'filename':'{0}.yaml'.format(function)}
    files = findAbstract('RaaC','function',query=query)

    if(len(files) == 0):
        return {"ErrorCode":"301","ErrorMsg":"The Function '{0}' doesn't exist on the database.".format(function)}

    if (version == '@latest'):
        return yaml.safe_load(files[-1].read().decode())

    ifFunctionExist = False
    desireFile = None
    for file in files:
        if(file.uniqueName == version):
            ifFunctionExist = True
            desireFile = file
    
    if (not ifFunctionExist):
        return {"ErrorCode":"301","ErrorMsg":"The Function '{0}' with the version of '{1}' doesn't exist on the database.".format(function,version)}
    
    return yaml.safe_load(desireFile.read().decode())