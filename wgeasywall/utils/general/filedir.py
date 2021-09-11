import glob
from pathlib import Path

def getFilesInDir(dirPath,fileExt):
    """
    List all the files with desired extension in a specific directory 
    """
    if not dirPath.is_dir():
        return {'ErrorCode':'404','ErrorMsg':'Directory {0} Not Found.'.format(dirPath)}

    filePattern = "{0}/{1}".format(str(dirPath),fileExt)
    filesList = glob.glob(filePattern)
    return filesList

def getFile(filePath):
    """
    Return contents of a file
    """
    if not Path(filePath).is_file():
        return {'ErrorCode':'404','ErrorMsg':'File Not Found.'}
    contents = Path(filePath).read_text().strip()
    return contents

import tempfile, shutil, os
def create_temporary_copy(path,networkName):
    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, networkName)
    shutil.copy2(path, temp_path)
    return temp_path