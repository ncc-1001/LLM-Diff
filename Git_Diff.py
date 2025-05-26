import subprocess

def git_diff(file_path_a: str, file_path_b: str, context: int = 3) -> str:
    """
    对比两个文件，返回它们之间的 unified diff。

    :param file_path_a: 第一个文件的路径
    :param file_path_b: 第二个文件的路径
    :param context: diff 时保留的上下文行数，默认 3
    :return: unified diff 字符串
    """
    cmd = [
        "git", "diff",
        "--no-index",
        f"-U{context}",
        file_path_a,
        file_path_b,
    ]
    # 运行 git diff，不抛异常（即使有差异也返回 stdout）
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in (0, 1):
        # returncode 1 表示有差异，0 表示无差异；其他值才是真正的错误
        raise RuntimeError(f"git diff 出错，returncode={proc.returncode}，stderr:\n{proc.stderr}")
    return proc.stdout

# 示例用法
if __name__ == "__main__":
    diff_text = git_diff("61/1.c", "62/1.c", context=5)
    print(diff_text)
