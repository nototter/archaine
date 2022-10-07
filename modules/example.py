"""
example alpine plugin

you could have as many defs and classes as you want, aslong as you have a help
help must be outside a class!!!! or else it wont work

all args will be in a list
"""

class example1:
    """
    an example class
    """
    def print_this(string):
        """
        an example definition in an example class
        """
        print(string)

    config = { 
        # you can have this in an external file, aslong as main file gets it in dictionary format
        # this is for your command help n stuff
        # alpine will raise an error if a key pair is missing
        "bonjour": "bonjour world",
        "hello": "hello world",
    }

def hello(args:list):
    """
    an example command
    """
    example1.print_this("hello world!")
    example1.print_this("your args are: {}".format(', '.join(args)))

def bonjour(args:list):
    """
    another example command
    """
    example1.print_this("baugette")
    example1.print_this("your args are: {}".format(', '.join(args)))

def ask(string):
    """
    an example of an unexecutable function
    """

    return input(string)

def functions():
    """
    put your executable functions here and your configuration
    """
    return (['hello', 'bonjour'], example1.config)