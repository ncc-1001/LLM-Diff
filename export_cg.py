import idautils
import idc
import idaapi

def generate_call_graph_text(output_file):
    cg = {}  # 存放函数调用关系，格式为 {caller: set(callee, ...)}
    for func_ea in idautils.Functions():
        caller = idc.get_func_name(func_ea)
        callees = set()
        # 遍历函数内所有指令
        for insn in idautils.FuncItems(func_ea):
            mnem = idc.print_insn_mnem(insn)
            # 同时记录 call 指令以及所有以 "j" 开头的跳转指令（如 jmp, jnz, jz, je, jne, ...）
            if mnem == "call" or mnem.startswith("j"):
                # 尝试获取指令的操作数（目标地址）
                opnd = idc.get_operand_value(insn, 0)
                callee = idc.get_func_name(opnd)
                if callee:
                    callees.add(callee)
        cg[caller] = callees

    # 将调用关系写入文件，每行格式为：caller -> callee1, callee2, ...
    with open(output_file, "w", encoding="utf-8") as f:
        for caller, callees in sorted(cg.items()):
            if callees:
                f.write("{} -> {}\n".format(caller, ", ".join(sorted(callees))))
            else:
                f.write("{} -> (无调用)\n".format(caller))
    idaapi.info("调用图文本文件已保存到：{}".format(output_file))

# 询问用户保存文件的路径
output_file = idaapi.ask_file(0, "*.txt", "保存调用图为文本文件")
if output_file:
    generate_call_graph_text(output_file)
