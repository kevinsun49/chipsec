class TPM_PUBLIC():
    # read version
    # read interface
    self._tpm = init_tpm(version, interface)

    def command():
        self._tpm.command()

    def send_command():
        self._tpm.send_command()

    def read_response():
        self._tpm.read_response()

    def dump_all():
        for reg in _tpm.list_of_regs:
            dump_register(reg)

    def dump_register(name):
        if name in _tpm.list_of_regs:
            #dump
        else:
            #be angry

class TPM_ABSTRACT_PRIVATE_ISH():
    list_of_regs = [] #implement this list

    def command():
        pass # need to implement

    def send_command():
        pass

    def read_response():
        pass

class TPM12(TPM_ABSTRACT_PRIVATE_ISH):
    list = [stuff]

    def command():
        return

    def send_command():
        return

    def read_response():
        return

class TPM20_FIFO(TPM_ABSTRACT_PRIVATE_ISH):
    list = [stuff]

    def command():
        return

    def send_command():
        return

    def read_response():
        return

class TPM20_CRB(TPM_ABSTRACT_PRIVATE_ISH):
    list = [stuff]

    def command():
        return

    def send_command():
        return

    def read_response():
        return

class TPM20_FIFO_LEGACY(TPM_ABSTRACT_PRIVATE_ISH):
    list = [stuff]

    def command():
        return

    def send_command():
        return

    def read_response():
        return
