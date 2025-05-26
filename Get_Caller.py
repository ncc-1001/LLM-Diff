import os
from collections import defaultdict
from tqdm import tqdm

def analyze_call_graph(file_path: str, target_function: str, up_depth: int = 3, down_depth: int = 3):
    callers = defaultdict(set)  # 被谁调用
    callees = defaultdict(set)  # 调用了谁

    print(f"🔍 正在解析调用图文件: {file_path}")
    if not os.path.exists(file_path):
        print("❌ 文件不存在，请确认路径正确。")
        return

    with open(file_path, 'r') as f:
        lines = f.readlines()

    for line in tqdm(lines, desc="📄 解析行", unit="行"):
        if '->' not in line:
            continue
        parts = line.split('->')
        if len(parts) != 2:
            continue
        caller = parts[0].strip()
        callee_str = parts[1].strip()

        if callee_str.lower() in ('', '(无调用)'):
            continue

        callee_list = [func.strip() for func in callee_str.split(',') if func.strip()]
        for callee in callee_list:
            callees[caller].add(callee)
            callers[callee].add(caller)

    def multi_layer_trace(start_funcs, graph, depth, direction=""):
        current_level = set(start_funcs)
        total_result = set()
        for d in range(depth):
            next_level = set()
            for func in current_level:
                neighbors = graph.get(func, set())
                for n in neighbors:
                    if n not in total_result:
                        next_level.add(n)
            total_result.update(next_level)
            current_level = next_level
            tqdm.write(f"🔄 已完成 {direction} 第 {d + 1} 层, 新增 {len(next_level)} 个函数")
        return total_result

    upward_funcs = multi_layer_trace([target_function], callers, up_depth, "↑ 向上追溯")
    downward_funcs = multi_layer_trace([target_function], callees, down_depth, "↓ 向下追溯")

    return {
        'upward_callers': sorted(upward_funcs),
        'downward_callees': sorted(downward_funcs)
    }

# ✅ 主函数：这里设置函数名和各个方向的层数
if __name__ == "__main__":
    target_func = "fixed_zl30136_Alm_Set"  # 👈 查哪个函数
    up_layer = 2                           # 👈 向上追几层
    down_layer = 2                         # 👈 向下追几层
    result = analyze_call_graph("CG/nokia_61_CG.txt", target_func, up_layer, down_layer)

    print(f"\n📌 函数：{target_func}")
    print(f"⬆️  调用者（向上{up_layer}层）:")
    for f in result['upward_callers']:
        print("  ", f)
    print(f"⬇️  被调用（向下{down_layer}层）:")
    for f in result['downward_callees']:
        print("  ", f)
