import os
import idc
import idautils
import idaapi

def safe_function_name(name):
    """清理函数名中的非法字符"""
    return name.replace(':', '_').replace('/', '_').replace('\\', '_').replace('*', '_')

def decompile_and_save():
    # 获取当前文件路径信息
    input_path = idc.get_input_file_path()
    if not input_path:
        print("错误：请先保存IDA数据库")
        return False

    # 创建输出目录
    base_dir = os.path.dirname(input_path)
    file_name = os.path.splitext(os.path.basename(input_path))[0]
    output_dir = os.path.join(base_dir, f"{file_name}_decompiled")
    
    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"创建目录失败: {str(e)}")
        return False

    # 获取所有函数
    total = 0
    success = 0
    for func_ea in idautils.Functions():
        total += 1
        func_name = idc.get_func_name(func_ea)
        
        try:
            # 反编译函数
            c_code = idaapi.decompile(func_ea)
            if not c_code:
                print(f"警告：无法反编译函数 {func_name}")
                continue
        except Exception as e:
            print(f"反编译 {func_name} 失败: {str(e)}")
            continue

        # 生成安全文件名
        safe_name = safe_function_name(func_name)
        output_path = os.path.join(output_dir, f"{safe_name}.c")
        
        # 写入文件
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(str(c_code))
            success += 1
        except Exception as e:
            print(f"写入 {func_name} 失败: {str(e)}")

    # 显示结果
    idaapi.info(f"反编译完成\n成功: {success}/{total}\n输出目录: {output_dir}")
    return True

if __name__ == "__main__":
    # 等待自动分析完成
    idaapi.auto_wait()
    
    # 执行反编译
    if not decompile_and_save():
        idaapi.warning("反编译过程出现错误，请检查输出窗口")
