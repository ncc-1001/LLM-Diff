import os
import idc
import idautils
import idaapi
import pickle
import ida_idaapi
import idaapi
import ida_nalt
import pathlib

idc.auto_wait()

bin_path = ida_nalt.get_input_file_path()
bin_name = os.path.basename(bin_path)

save_path =  bin_name + '.export'

idaapi.ida_expr.eval_idc_expr(None, ida_idaapi.BADADDR,
                              f'BinExportBinary("{save_path}");')

idc.qexit(0)
