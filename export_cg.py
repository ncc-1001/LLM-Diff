import idautils
import idc
import idaapi
import os

def generate_call_graph_text(output_file):
    cg = {}  # 存放函数调用关系，格式为 {caller: set(callee, ...)}
    for func_ea in idautils.Functions():
        caller = idc.get_func_name(func_ea)
        callees = set()
        # 遍历函数内所有指令
        for insn in idautils.FuncItems(func_ea):
            mnem = idc.print_insn_mnem(insn)
            # 同时记录 call 指令以及所有以 "j" 开头的跳转指令
            if mnem == "call" or mnem.startswith("j"):
                opnd = idc.get_operand_value(insn, 0)
                callee = idc.get_func_name(opnd)
                if callee:
                    callees.add(callee)
        cg[caller] = callees

    # 自动创建输出路径
    output_dir = os.path.dirname(idc.get_input_file_path())
    os.makedirs(output_dir, exist_ok=True)
    
    # 写入文件
    with open(output_file, "w", encoding="utf-8") as f:
        for caller, callees in sorted(cg.items()):
            line = f"{caller} -> {', '.join(sorted(callees)) if callees else '(无调用)'}\n"
            f.write(line)
    idaapi.info(f"调用图已自动保存到：{output_file}")

# 自动生成文件路径
input_path = idc.get_input_file_path()
if input_path:
    base_name = os.path.splitext(os.path.basename(input_path))[0]
    output_file = os.path.join(
        os.path.dirname(input_path),
        f"{base_name}_cg.txt"
    )
    generate_call_graph_text(output_file)
else:
    idaapi.warning("无法获取当前文件路径，请先保存数据库")
