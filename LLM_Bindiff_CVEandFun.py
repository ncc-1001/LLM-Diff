from Get_Caller import analyze_call_graph
from Git_Diff import git_diff
import os
import json
from QwenBot import QwenBot

MAX_PROMPT_LENGTH = 131072  # 128K 字符限制
# RESULTS_FILE = "LLM_results/filtered_results.json"
# ANALYSIS_FILE = "LLM_results/analysis_results.json"
# FIRMWARE61_DIR = "../61"
# FIRMWARE62_DIR = "../62"
# CALLGRAPH61_FILE = "CG/nokia_61_CG_cleaned.txt"
# CALLGRAPH62_FILE = "CG/nokia_62_CG_cleaned.txt"
RESULTS_FILE = "bindiff_results/tidy_results.json"
ANALYSIS_FILE = "LLM_results/analysis_results_tidy.json"
FIRMWARE61_DIR = "../tidy_original"
FIRMWARE62_DIR = "../tidy_patched"
CALLGRAPH61_FILE = "CG/tidy_original_cg_cleaned.txt"
CALLGRAPH62_FILE = "CG/tidy_patched_cg_cleaned.txt"

PROMPT = '''你是一个CVE漏洞分析专家，掌握了所有与代码相关的CVE漏洞类型以及成因。现在我将会向你发送一个目标函数及其调用链上的相关函数再一次更新中发生的git diff的变化，根据你掌握的CVE漏洞相关知识，判断这样的更新中是否修复了bug
由于长度限制，在发送时可能无法完全发送，请根据最后的提示信息进行判断，如果提示未发送完成则请先不进行分析，待提示发送完全后统一进行分析。
CVE案例介绍：

CVE-2020-14364：
漏洞类型：越界读写
成因：USB数据包长度检查逻辑错误导致越界访问
漏洞代码示例： ```c
     s->setup_len = (s->setup_buf[7] << 8) | s->setup_buf[6];
     if (s->setup_len > sizeof(s->data_buf)) { /* 检查在赋值之后 */ }
     ```
CVE-2017-5638：
漏洞类型：输入验证绕过
成因：Jakarta插件异常处理未过滤Content-Type头
漏洞代码特征：```java
     LocalizedTextUtil.findText(..., valueStack...) // 直接执行OGNL表达式
     ```

[Caller]
{$Caller$}
[Caller end]

[Callee]
{$Callee$}
[Callee end]

[TFunction]
{$TFunction$}
[TFunction end]

请详细说明这两个版本在此次更新中所做的改动，并判断这次改动中是否存在漏洞风险被修复，由于这份代码是两个版本的对应函数，请注意分析这两者其中的差异是Patch还是漏洞修复，还是可能的函数功能变更，并详细说明漏洞类型或变更方向。
请重点关注[$Target$]函数在此次更新中的变化，并以其为基准进行判断，请忽略由于对应变量变量名的更改或者是对应的硬地址编码更改导致的变化，这可能是由于反编译导致的差异，不能算作漏洞，数组的索引方式的变化（地址指针变为数组下标）不作为漏洞，新版本未修复的不算做漏洞。
并严格按照以下格式回复，不要有多余的回答，回答时只保留标题后面的描述文字请不要保留，并加上自己的回答：
[差异分析]：Bug/Functional Change
[漏洞类型]：缓冲区溢出/格式化字符串等
[漏洞成因]：说明具体的漏洞成因
[漏洞代码段]：将两个版本之间包含漏洞和修复漏洞的代码段指出
[函数功能]：简略描述这两段代码实现了什么功能，修改部分在函数整体当中的作用。
[漏洞利用方式]：如果不是修复漏洞则为无，否则详细说明可行的漏洞利用方式，如构造怎样的输入或变量可以实现攻击效果
[漏洞利用效果]：如果不是修复漏洞则为无，否则详细说明漏洞利用可能达到的攻击效果
[漏洞评分]：1-10的整数，1-3分为轻微漏洞，例如使用不安全的函数printf，4-6分为中等危险漏洞，7-10分为高度疑似漏洞
'''


def resolve_c_filepath(dir_path, func_name):
    """
    根据函数名和目录，返回带 .c 后缀的文件绝对路径（存在即返回），否则 None
    """
    path = os.path.join(dir_path, func_name)
    if os.path.exists(path):
        return path
    if not func_name.endswith('.c'):
        path_c = os.path.join(dir_path, func_name + '.c')
        if os.path.exists(path_c):
            return path_c
    return None


def load_results(file_path):
    if not os.path.exists(file_path):
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump([], f, ensure_ascii=False, indent=2)
        return []
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_existing_analysis(file_path):
    if not os.path.exists(file_path):
        return {}
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_analysis(file_path, data):
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


class Refiner:
    def __init__(self):
        self.bot = QwenBot()
        self.prompt_template = PROMPT

    def make_prompt(self, caller, callee, target_function, target_name, complete):
        prompt = self.prompt_template.replace("{$Caller$}", caller or "(无)") \
                                     .replace("{$Callee$}", callee or "(无)") \
                                     .replace("{$TFunction$}", target_function or "(无)") \
                                     .replace("[$Target$]", target_name or "(未知目标函数)")
        if not complete:
            prompt += "\n⚠️ 当前信息未发送完整，请等待完整信息后再分析。"
        return prompt

    def query2bot(self, caller, callee, target_function, target_name, complete):
        query = self.make_prompt(caller, callee, target_function, target_name, complete)
        response = self.bot.send_message(query)
        with open("refiner.txt", "a", encoding='utf-8') as f:
            f.write(query + "\n")
        return response


class RefinerRunner(Refiner):
    def __init__(self):
        super().__init__()

    def get_diff_text(self, filepath1, filepath2):
        if not filepath1 or not filepath2:
            return None
        diff = git_diff(filepath1, filepath2, context=3)
        if diff and diff.strip():
            return diff
        try:
            with open(filepath1, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception:
            return "(无差异)"

    def collect_related_diffs(self, funcs, dir1, dir2):
        diffs = []
        for fn in funcs:
            path1 = resolve_c_filepath(dir1, fn)
            path2 = resolve_c_filepath(dir2, fn)
            diff = self.get_diff_text(path1, path2)
            if diff:
                diffs.append(diff)
        return "\n".join(diffs) if diffs else "(无)"

    def process_entry(self, entry):
        func61 = entry.get("function_61")
        func62 = entry.get("function_62")
        if not func61 or func61 != func62:
            print(f"⚠️ 跳过函数名不一致的条目: {func61} vs {func62}")
            return None, None
        target_full = func61

        # 1. 获取目标函数 diff
        tpath1 = resolve_c_filepath(FIRMWARE61_DIR, target_full)
        tpath2 = resolve_c_filepath(FIRMWARE62_DIR, target_full)
        target_diff = self.get_diff_text(tpath1, tpath2) or "(无差异)"

        # 2. 解析调用图
        base = os.path.splitext(target_full)[0]
        cg61 = analyze_call_graph(CALLGRAPH61_FILE, base, 1, 2)
        cg62 = analyze_call_graph(CALLGRAPH62_FILE, base, 1, 2)
        callers = set(cg61['upward_callers']) & set(cg62['upward_callers'])
        callees = set(cg61['downward_callees']) & set(cg62['downward_callees'])

        # 3. 收集 diffs
        caller_diffs = self.collect_related_diffs(callers, FIRMWARE61_DIR, FIRMWARE62_DIR)
        callee_diffs = self.collect_related_diffs(callees, FIRMWARE61_DIR, FIRMWARE62_DIR)

        # 4. 检查 prompt 长度
        prompt = self.make_prompt(caller_diffs, callee_diffs, target_diff, target_full, True)
        if len(prompt) > MAX_PROMPT_LENGTH:
            print(f"❌ Prompt 超过最大长度（{len(prompt)} 字符），跳过 {target_full}")
            return target_full, None

        # 5. 调用模型
        analysis = self.query2bot(caller_diffs, callee_diffs, target_diff, target_full, True)
        return target_full, {"analysis": analysis}

    def run(self):
        entries = load_results(RESULTS_FILE)
        existing = load_existing_analysis(ANALYSIS_FILE)

        for entry in entries:
            func61 = entry.get("function_61")
            func62 = entry.get("function_62")
            if not func61 or func61 != func62:
                print(f"⚠️ 跳过函数名不一致的条目: {func61} vs {func62}")
                continue
            target_full = func61

            # 提前检查是否已分析过，避免不必要的处理
            if target_full in existing:
                print(f"ℹ️ 已存在分析结果，跳过 {target_full}")
                continue

            target, result = self.process_entry(entry)
            if not target or result is None:
                continue

            existing[target] = result
            save_analysis(ANALYSIS_FILE, existing)
            print(f"✅ 完成分析并保存: {target}")


if __name__ == "__main__":
    runner = RefinerRunner()
    runner.run()
