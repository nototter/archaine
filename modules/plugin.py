"""
DO NOT RENAME ME OR DELETE ME!!!!!!
"""
import os, sys
import importlib
  
plugins = {}

def load(folder="plugins"):
    r = {}

    for item in os.listdir(f"./{folder}"):
        if item == "plugin.py": continue
        if ".py" in item:
            
            item = item.replace('.py','')

            plugins[item] = importlib.import_module(f'{folder}.{item}')

            r[item] = (f'{folder}.{item}', plugins[item].functions(), plugins[item])
        
    return (plugins, r)

def function(target, arg=False, plugin=None):

    if plugin == None:
        err = 0
        for function in plugins:
            if target.replace(".py", "") in str(function):
                func = getattr(plugins[function], function, None)

                if func:
                    func(arg)
                    return True
                else:
                    err += 1

                if err == len(plugins):
                    raise AttributeError("function doesnt exist")
        

    else:
        err = 0
        try:
            func = getattr(plugin, target)
        except AttributeError:
            err += 1
        else:
            if not arg:
                func()
                return
            else:
                func(arg)
                return

        if err == len(plugins):
            raise AttributeError("function doesnt exist")