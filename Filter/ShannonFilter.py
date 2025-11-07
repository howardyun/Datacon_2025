import math
import os
import sys
from collections import Counter


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
                high_entropy_files.append({
                    'filename': file,  # 只记录hash文件名
                    'filepath': file_path.split('/')[-1],
                    'entropy': entropy_value
                })
                print(f"高熵文件 detected: {file} (熵值: {entropy_value:.4f})")

    return high_entropy_files


def save_results(high_entropy_files, output_file="high_entropy_files.txt"):
    """
    将高熵文件名保存到文件
    """
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("高熵文件列表:\n")
        f.write("=" * 50 + "\n")

        for file_info in high_entropy_files:
            f.write(f"文件名: {file_info['filename']}\n")
            f.write(f"完整路径: {file_info['filepath']}\n")
            f.write(f"熵值: {file_info['entropy']:.4f}\n")
            f.write("-" * 30 + "\n")

    print(f"\n结果已保存到: {output_file}")


def main():
    """
    主函数
    """
    if len(sys.argv) < 2:
        print("使用方法: python entropy_scanner.py <目录路径> [熵阈值]")
        print("示例: python entropy_scanner.py ./files 5.0")
        return

    directory_path = sys.argv[1]

    # 设置熵阈值，默认为5.0
    entropy_threshold = 5.0
    if len(sys.argv) > 2:
        try:
            entropy_threshold = float(sys.argv[2])
        except ValueError:
            print("警告: 无效的熵阈值，使用默认值5.0")

    if not os.path.isdir(directory_path):
        print(f"错误: 目录不存在: {directory_path}")
        return

    print(f"开始扫描目录: {directory_path}")
    print(f"熵阈值: {entropy_threshold}")
    print("-" * 50)

    # 扫描目录
    high_entropy_files = scan_directory(directory_path, entropy_threshold)

    # 输出摘要
    print(f"\n扫描完成!")
    print(f"总发现高熵文件: {len(high_entropy_files)} 个")

    if high_entropy_files:
        # 按熵值排序
        high_entropy_files.sort(key=lambda x: x['entropy'], reverse=True)

        print("\n高熵文件列表 (按熵值降序):")
        for file_info in high_entropy_files:
            print(f"  {file_info['filename']} - 熵值: {file_info['entropy']:.4f}")

        # 保存结果到文件
        save_results(high_entropy_files)
    else:
        print("未发现高熵文件")


if __name__ == "__main__":
    main()