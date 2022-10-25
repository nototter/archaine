class scriptInject():
    def __init__(self, terminalType:int=1):
        """
        terminal types:
        0: cmd (conpty)
        1: powershell
        2: bash
        3: ncat bash
        4: ncat bat
        5: powershell base64
        6: python (most features)
        """

        if terminalType not in range(6): raise KeyError("not in terminal types")
        self.type = terminalType

        return True

    def cmdPTY():
        return open("/injects/cmdPTY.inj", "r").read()

    def powershell():
        return open("/injects/powershell.inj", "r").read()

    def bash():
        return open("/injects/bash.ink", "r").read()

    def ncatBash():
        return open("/injects/ncatBash.inj", "r").read()

    def ncatBatch():
        return open("/injects/ncatBat.inj", "r").read()

    def powershell64():
        return open("/injects/powershell64.inj", "r")
        
    def python():
        return open("/injects/python.inj", "r")

    
        