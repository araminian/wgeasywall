import os

def get_wgeasywall_config_location():
    home = os.getenv("HOME")
    return "{0}{1}".format(home,"/.wgeasywall/")

def get_mongo_configuration_location():
    return "{0}{1}".format(get_wgeasywall_config_location(),"mongo.yaml")