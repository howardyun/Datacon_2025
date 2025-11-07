import os
import subprocess
import json
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed

def extractTokenandFile(scan_result):
    # 遍历findings中的每个条目
    row_data = []  # 用来存储每一行的file和raw信息
    scan_result = json.loads(scan_result)
    for finding in scan_result.get('findings', []):
        # 检查SourceMetadata是否存在
        source_metadata = finding.get('SourceMetadata')
        if source_metadata:
            # 从SourceMetadata提取file和Raw
            source_data = source_metadata.get('Data', {})
            filesystem_data = source_data.get('Filesystem', {})

            file_info = filesystem_data.get('file')
            raw_info = finding.get('Raw')

            if file_info and raw_info:
                if ".git" in file_info:
                    file_info = ".git"  # 只记录为'.git'
                else:
                    file_info = file_info.split("\\")[-1]
                # 将提取的file和Raw信息存入字典
                row_data.append({
                    'file': file_info,
                    'raw': raw_info
                })
    return row_data

def scan_with_trufflehog(folder_path):
    """
    使用 TruffleHog 扫描指定文件夹中的代码仓库
    :param folder_path: 要扫描的文件夹路径
    :return: 仓库名称和扫描结果 (JSON 格式字符串)，如果没有结果返回 None
    """
    try:
        cmd=[
                "/home/szk/.local/bin/trufflehog", "filesystem",
                folder_path,
                "--results=verified,unknown", "--json"
            ]
        cmd_str = " ".join(cmd)
        # 执行 TruffleHog 扫描
        result = subprocess.run(
            cmd_str,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=True
        )

        # 分割结果输出为 JSON 字符串列表
        json_strings = result.stdout.split('\n')
        # 转换为 JSON 对象列表
        json_objects = [json.loads(js) for js in json_strings if js.strip()]

        # 检查最后一个 JSON 对象中的 verified_secrets 和 unverified_secrets
        if json_objects[-1]["verified_secrets"] == 0 and json_objects[-1]["unverified_secrets"] == 0:
            print(f"没有发现敏感信息: {folder_path}")
            merged_json = {"findings": []}
            return None  # 返回空表示没有结果
        else:
            print(f"发现敏感信息: {folder_path}")
            merged_json=extractTokenandFile(json.dumps({"findings": json_objects}))
            return os.path.basename(folder_path), merged_json

    except Exception as e:
        print(f"扫描时发生错误: {e}")
        return None


def save_to_json(data, output_json_path):
    """
    将扫描结果保存为 JSON 数组文件
    :param data: 扫描结果列表，每项为 (仓库名称, 扫描结果 JSON 字符串)
    :param output_json_path: 保存的 JSON 文件路径
    """

    # 写入 JSON 文件
    with open(output_json_path, "w", encoding="utf-8") as jsonfile:
        json.dump(data, jsonfile, indent=4, ensure_ascii=False)

    print(f"结果已保存到 JSON 文件: {output_json_path}")


def process_single_folder_parallel_json(folder_path, output_dir, max_workers=4):
    """
    单独处理一个文件夹，并行扫描其下的所有文件（而非子文件夹），并将结果保存为 JSON 数组
    :param folder_path: 要处理的文件夹路径
    :param output_dir: 保存结果的根目录
    :param max_workers: 最大并行线程数
    """
    print(f"正在并行处理文件夹: {folder_path}")
    scan_results = []  # 用于存储扫描结果
    
    # 关键修改：筛选文件夹下的所有文件（而非子文件夹）
    files = [
        os.path.join(folder_path, file_name)
        for file_name in os.listdir(folder_path)
        if os.path.isfile(os.path.join(folder_path, file_name))  # 替换 isdir 为 isfile
    ]

    # 使用线程池并行扫描文件
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 关键修改：任务对象映射为“任务-文件路径”
        future_to_file = {
            executor.submit(scan_with_trufflehog, file_path): file_path
            for file_path in files
        }

        for future in as_completed(future_to_file):
            file_path = future_to_file[future]
            try:
                result = future.result()
                if result:  # 如果有扫描结果
                    # 关键修改：用文件名替代原仓库名，保持结果格式逻辑
                    file_name = os.path.basename(file_path)
                    for i in result[1]:
                        scan_results.append({"file_hash": file_name, "value": i.get('raw')})
            except Exception as e:
                print(f"扫描文件 {file_path} 时发生错误: {e}")

    # 保存结果逻辑不变（仅文件名前缀仍用文件夹名，可按需调整）
    if scan_results:
        folder_name = os.path.basename(folder_path)
        output_json_path = os.path.join(output_dir, f"{folder_name}_file_scan_results.json")
        save_to_json(scan_results, output_json_path)
        print(f"扫描结果已保存至: {output_json_path}")
    else:
        print(f"没有在 {folder_path} 的文件中找到任何敏感信息。")



if __name__ == "__main__":
    # 定义根目录和输出结果根目录
    trufflehog_output_dir = "/home/szk/datacon2025_result"
    os.makedirs(trufflehog_output_dir, exist_ok=True)  # 如果目录不存在，则创建


    process_single_folder_parallel_json("/home/szk/all_files_hash", trufflehog_output_dir, max_workers=10)
