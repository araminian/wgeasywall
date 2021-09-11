import wgeasywall.utils.wireguard.models as wg_models
import configparser
from pathlib import Path , PurePath
from pydantic import ValidationError
import os


def generate_interface(interface: wg_models.InterfaceModel):

    interfaceDict = {}

    commentKey = "# {0} ".format(interface.CommentKey)
    interfaceDict [commentKey] = interface.CommentValue
    interfaceDict ['Address'] = interface.Address
    interfaceDict ['ListenPort'] = interface.ListenPort
    interfaceDict ['PrivateKey'] = interface.PrivateKey.Key
    
    
    return interfaceDict

def generate_peer(peer: wg_models.PeerModel):

    peerDict = {}

    commentKey = "# {0} ".format(peer.CommentKey)
    peerDict [commentKey] = peer.CommentValue

    peerDict ['PublicKey'] = peer.PublicKey.Key
    if (peer.PreSharedKey != None):
        peerDict ['PreSharedKey'] = peer.PreSharedKey.Key

    peerDict ['AllowedIPs'] = ", ".join(peer.AllowedIPs)

    if (peer.Endpoint == None):
        return peerDict

    EndpointAddress = peer.Endpoint.Address
    EndpointHostname = peer.Endpoint.Hostname

    if EndpointAddress:

        peerDict ['Endpoint'] = "{0}:{1}".format(EndpointAddress,peer.Endpoint.Port)
    else:
        peerDict ['Endpoint'] = "{0}:{1}".format(EndpointHostname,peer.Endpoint.Port)
    return peerDict


def generate_wg_conf_file(configModel: wg_models.ConfigComponentsModel):

    Interface = configModel.Interface
    Peers = configModel.Peers
    ConfigPath = configModel.ConfigPath

    path = PurePath(ConfigPath)
    parentPath = path.parent
    if(not Path(parentPath).exists()):
        os.mkdir(parentPath)
    if(Path(ConfigPath).exists()):
        os.remove(path)

    interfaceConfig = configparser.ConfigParser(strict=False,defaults=None)
    interfaceConfig.optionxform = str

    interfaceConfig['Interface'] = Interface

    with open(ConfigPath, 'a') as interfaceConfigFile:
        interfaceConfig.write(interfaceConfigFile)

    for p in Peers:
        with open(ConfigPath , 'a') as peerConfigFile:
            configPeer = configparser.ConfigParser(strict=False,defaults=None)
            configPeer.optionxform = str
            configPeer['Peer'] = p
            configPeer.write(peerConfigFile)