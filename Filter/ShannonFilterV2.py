import math
import os
import sys
import json
from collections import Counter
# python3 Filter/ShannonFilterV2.py TestData/all_files_hash 5


def calculate_shannon_entropy(data):
    """
    计算字符串的香农熵
    """
    if not data:
        return 0

    # 计算每个字符出现的频率
    counter = Counter(data)
    data_length = len(data)

    # 计算熵值
    entropy = 0.0
    for count in counter.values():
        probability = count / data_length
        entropy -= probability * math.log2(probability)

    return entropy


def analyze_file(file_path, entropy_threshold=5.0):
    """
    分析文件的香农熵，返回是否超过阈值
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()

        if not content:
            return False, 0.0

        # 计算熵值
        entropy = calculate_shannon_entropy(content)

        # 检查是否超过阈值
        if entropy >= entropy_threshold:
            return True, entropy
        else:
            return False, entropy

    except Exception as e:
        print(f"Error analyzing file {file_path}: {e}")
        return False, 0.0


def scan_directory(directory_path, entropy_threshold=5.0):
    """
    扫描目录下所有文件，记录高熵文件
    """
    high_entropy_files = []

    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)

            # 跳过目录本身
            if os.path.isdir(file_path):
                continue

            # 分析文件
            is_high_entropy, entropy_value = analyze_file(file_path, entropy_threshold)

            if is_high_entropy:
                file_info = {
                    'filename': file,  # hash文件名
                    'filepath': file_path,
                    'entropy': round(entropy_value, 4),
                    'size': os.path.getsize(file_path)
                }
                high_entropy_files.append(file_info)
                print(f"High entropy file detected: {file} (entropy: {entropy_value:.4f})")

    return high_entropy_files


def save_results_to_json(high_entropy_files, output_file="high_entropy_files.json"):
    """
    将高熵文件信息保存为JSON格式
    """
    result_data = {
        "scan_summary": {
            "total_files_scanned": len(high_entropy_files),
            "entropy_threshold_used": entropy_threshold,
            "scan_timestamp": None  # 可以在main函数中设置
        },
        "high_entropy_files": high_entropy_files
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result_data, f, ensure_ascii=False, indent=2)

    print(f"Results saved to: {output_file}")


def main():
    """
    主函数
    """
    if len(sys.argv) < 2:
        print("Usage: python entropy_scanner.py <directory_path> [entropy_threshold]")
        print("Example: python entropy_scanner.py ./files 5.0")
        return

    directory_path = sys.argv[1]

    # 设置熵阈值，默认为5.0
    global entropy_threshold
    entropy_threshold = 5.0
    if len(sys.argv) > 2:
        try:
            entropy_threshold = float(sys.argv[2])
        except ValueError:
            print("Warning: Invalid entropy threshold, using default value 5.0")

    if not os.path.isdir(directory_path):
        print(f"Error: Directory does not exist: {directory_path}")
        return

    print(f"Scanning directory: {directory_path}")
    print(f"Entropy threshold: {entropy_threshold}")
    print("-" * 50)

    # 扫描目录
    high_entropy_files = scan_directory(directory_path, entropy_threshold)

    # 输出摘要
    print(f"\nScan completed!")
    print(f"Total high entropy files found: {len(high_entropy_files)}")

    if high_entropy_files:
        # 按熵值排序
        high_entropy_files.sort(key=lambda x: x['entropy'], reverse=True)

        print("\nHigh entropy files (sorted by entropy):")
        for file_info in high_entropy_files:
            print(f"  {file_info['filename']} - entropy: {file_info['entropy']}")

        # 保存结果到JSON文件
        save_results_to_json(high_entropy_files)

        # 也保存一个简化的版本，只包含文件名
        simplified_result = {
            "high_entropy_filenames": [file_info['filename'] for file_info in high_entropy_files]
        }
        with open("high_entropy_filenames.json", 'w', encoding='utf-8') as f:
            json.dump(simplified_result, f, ensure_ascii=False, indent=2)
        print("Simplified filename list saved to: high_entropy_filenames.json")

    else:
        print("No high entropy files found")


if __name__ == "__main__":
    main()