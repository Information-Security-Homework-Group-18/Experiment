import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time

class S_DES:
    """S-DES 加密解密算法类"""

    # 2.4 转换装置设定
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]        # 密钥扩展置换 P10
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]                # 密钥压缩置换 P8
    IP = [2, 6, 3, 1, 4, 8, 5, 7]                 # 初始置换 IP
    IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]              # 最终置换 IP^-1
    EPBOX = [4, 1, 2, 3, 2, 3, 4, 1]               # 扩展置换 EPBox
    SPBOX = [2, 4, 3, 1]                           # 置换 SPBox
    LEFT_SHIFT_1 = [2, 3, 4, 5, 1]                 # 左移1位
    LEFT_SHIFT_2 = [3, 4, 5, 1, 2]                 # 左移2位

    # S-Box 定义
    SBOX1 = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 0, 2]
    ]

    SBOX2 = [
        [0, 1, 2, 3],
        [2, 3, 1, 0],
        [3, 0, 1, 2],
        [2, 1, 0, 3]
    ]

    def __init__(self):
        self.key = None
        self.subkeys = []  # 存储两个子密钥 k1, k2

    def set_key(self, key_str):
        """设置10-bit密钥"""
        if len(key_str) != 10 or not all(b in '01' for b in key_str):
            raise ValueError("密钥必须是10位二进制字符串")
        self.key = key_str
        self._generate_subkeys()

    def _generate_subkeys(self):
        """根据密钥生成两个子密钥 k1 和 k2"""
        # 步骤1: 对密钥应用 P10 置换
        p10_result = ''.join([self.key[i - 1] for i in self.P10])

        # 步骤2: 将结果分为左右两部分
        left_half = p10_result[:5]
        right_half = p10_result[5:]

        # 步骤3: 对左右部分分别进行左移
        left_shifted_1 = ''.join([left_half[i - 1] for i in self.LEFT_SHIFT_1])
        right_shifted_1 = ''.join([right_half[i - 1] for i in self.LEFT_SHIFT_1])

        # 步骤4: 合并后应用 P8 得到 k1
        merged_1 = left_shifted_1 + right_shifted_1
        k1 = ''.join([merged_1[i - 1] for i in self.P8])

        # 步骤5: 对第一次移位后的结果再进行左移 (第二次移位)
        left_shifted_2 = ''.join([left_shifted_1[i - 1] for i in self.LEFT_SHIFT_2])
        right_shifted_2 = ''.join([right_shifted_1[i - 1] for i in self.LEFT_SHIFT_2])

        # 步骤6: 合并后应用 P8 得到 k2
        merged_2 = left_shifted_2 + right_shifted_2
        k2 = ''.join([merged_2[i - 1] for i in self.P8])

        self.subkeys = [k1, k2]

    def _xor(self, a, b):
        """对两个等长二进制字符串进行异或操作"""
        return ''.join('1' if x != y else '0' for x, y in zip(a, b))

    def _sbox_lookup(self, sbox, input_bits):
        """在指定S-Box中查找输出"""
        row = int(input_bits[0] + input_bits[3], 2)  # 第1位和第4位组成行
        col = int(input_bits[1] + input_bits[2], 2)  # 第2位和第3位组成列
        value = sbox[row][col]
        return format(value, '02b')  # 返回2位二进制

    def _f_function(self, right_half, subkey):
        """轮函数 F(R, K)"""
        # 步骤1: 扩展置换 EPBox
        expanded = ''.join([right_half[i - 1] for i in self.EPBOX])

        # 步骤2: 与子密钥异或
        xor_result = self._xor(expanded, subkey)

        # 步骤3: 分割成两个4位块，分别通过 S-Box
        left_4bits = xor_result[:4]
        right_4bits = xor_result[4:]

        sbox1_output = self._sbox_lookup(self.SBOX1, left_4bits)
        sbox2_output = self._sbox_lookup(self.SBOX2, right_4bits)

        # 步骤4: 合并并应用 SPBox 置换
        combined = sbox1_output + sbox2_output
        spboxed = ''.join([combined[i - 1] for i in self.SPBOX])

        return spboxed

    def _feistel_round(self, data, subkey):
        """执行一轮Feistel结构"""
        left_half = data[:4]
        right_half = data[4:]
        f_output = self._f_function(right_half, subkey)
        new_left = self._xor(left_half, f_output)
        return right_half + new_left  # 注意交换左右半部

    def encrypt(self, plaintext):
        """加密一个8-bit明文"""
        if len(plaintext) != 8 or not all(b in '01' for b in plaintext):
            raise ValueError("明文必须是8位二进制字符串")

        # 步骤1: 初始置换 IP
        ip_result = ''.join([plaintext[i - 1] for i in self.IP])

        # 步骤2: 第一轮 Feistel
        round1_result = self._feistel_round(ip_result, self.subkeys[0])

        # 步骤3: 第二轮 Feistel
        round2_result = self._feistel_round(round1_result, self.subkeys[1])

        # 步骤4: 最终置换 IP^-1
        ciphertext = ''.join([round2_result[i - 1] for i in self.IP_INV])

        return ciphertext

    def decrypt(self, ciphertext):
        """解密一个8-bit密文"""
        if len(ciphertext) != 8 or not all(b in '01' for b in ciphertext):
            raise ValueError("密文必须是8位二进制字符串")

        # 步骤1: 初始置换 IP
        ip_result = ''.join([ciphertext[i - 1] for i in self.IP])

        # 步骤2: 第一轮 Feistel (使用 k2)
        round1_result = self._feistel_round(ip_result, self.subkeys[1])

        # 步骤3: 第二轮 Feistel (使用 k1)
        round2_result = self._feistel_round(round1_result, self.subkeys[0])

        # 步骤4: 最终置换 IP^-1
        plaintext = ''.join([round2_result[i - 1] for i in self.IP_INV])

        return plaintext

    def encrypt_ascii(self, ascii_text):
        """加密ASCII字符串（每个字符作为1 Byte）"""
        result = []
        for char in ascii_text:
            byte_str = format(ord(char), '08b')
            encrypted_byte = self.encrypt(byte_str)
            result.append(encrypted_byte)
        return ''.join(result)

    def decrypt_ascii(self, binary_string):
        """解密由多个8-bit组成的二进制串，还原为ASCII字符串"""
        if len(binary_string) % 8 != 0:
            raise ValueError("输入的二进制字符串长度必须是8的倍数")

        result = []
        for i in range(0, len(binary_string), 8):
            byte_str = binary_string[i:i+8]
            decrypted_byte = self.decrypt(byte_str)
            # 尝试转换为ASCII字符，如果超出范围则保留二进制
            try:
                char_code = int(decrypted_byte, 2)
                if 0 <= char_code <= 127:
                    result.append(chr(char_code))
                else:
                    result.append(f"[{decrypted_byte}]")  # 非可打印字符
            except:
                result.append(f"[{decrypted_byte}]")
        return ''.join(result)


# ============================
# 暴力破解功能
# ============================

def brute_force_attack(sdes_instance, known_plaintext, known_ciphertext, progress_callback=None):
    """
    暴力破解S-DES密钥。
    :param sdes_instance: S_DES实例
    :param known_plaintext: 已知明文 (8-bit)
    :param known_ciphertext: 已知密文 (8-bit)
    :param progress_callback: 进度回调函数
    :return: 找到的密钥列表
    """
    found_keys = []
    total_keys = 2**10  # 1024个可能的密钥

    start_time = time.time()
    for i in range(total_keys):
        key_str = format(i, '010b')  # 生成10位二进制密钥
        sdes_instance.set_key(key_str)
        try:
            encrypted = sdes_instance.encrypt(known_plaintext)
            if encrypted == known_ciphertext:
                found_keys.append(key_str)
        except Exception:
            continue  # 忽略异常

        # 调用进度回调
        if progress_callback and i % 100 == 0:  # 每100次更新一次进度
            elapsed_time = time.time() - start_time
            progress = (i + 1) / total_keys * 100
            progress_callback(progress, elapsed_time, len(found_keys))

    end_time = time.time()
    return found_keys, end_time - start_time

def encrypt_action(self):
    """执行加密操作"""
    try:
        key = self.key_entry.get().strip()
        plaintext = self.plaintext_entry.get().strip()

        self.sdes.set_key(key)

        # 判断输入是8-bit还是ASCII
        if len(plaintext) == 8 and all(b in '01' for b in plaintext):
            ciphertext = self.sdes.encrypt(plaintext)
            output = f"明文: {plaintext}\n密文: {ciphertext}"
        else:
            # 假设是ASCII字符串
            ciphertext_binary = self.sdes.encrypt_ascii(plaintext)
            # 将二进制密文按字节分割显示
            chunks = [ciphertext_binary[i:i+8] for i in range(0, len(ciphertext_binary), 8)]
            ciphertext_display = ' '.join(chunks)
            output = f"明文 (ASCII): {plaintext}\n密文 (二进制): {ciphertext_display}"

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, output)
        self.status_label.config(text="加密成功！")

    except Exception as e:
        messagebox.showerror("错误", str(e))
        self.status_label.config(text="加密失败！")

def decrypt_action(self):
    """执行解密操作"""
    try:
        key = self.key_entry.get().strip()
        ciphertext = self.plaintext_entry.get().strip()

        self.sdes.set_key(key)

        # 判断输入是8-bit还是二进制串
        if len(ciphertext) == 8 and all(b in '01' for b in ciphertext):
            plaintext = self.sdes.decrypt(ciphertext)
            output = f"密文: {ciphertext}\n明文: {plaintext}"
        elif len(ciphertext) > 0 and all(b in '01' for b in ciphertext) and len(ciphertext) % 8 == 0:
            # 解密整个二进制串
            plaintext_ascii = self.sdes.decrypt_ascii(ciphertext)
            output = f"密文 (二进制): {ciphertext}\n明文 (ASCII): {plaintext_ascii}"
        else:
            raise ValueError("密文格式错误，应为8位二进制或8的倍数位二进制串")

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, output)
        self.status_label.config(text="解密成功！")

    except Exception as e:
        messagebox.showerror("错误", str(e))
        self.status_label.config(text="解密失败！")

def brute_force_action(self):
    """启动暴力破解线程"""
    try:
        plaintext = self.plaintext_entry.get().strip()
        ciphertext = self.output_text.get("1.0", tk.END).strip().split('\n')[1].split(': ')[1]  # 从输出中提取密文

        if len(plaintext) != 8 or not all(b in '01' for b in plaintext):
            raise ValueError("暴力破解需要8-bit明文")

        if len(ciphertext) != 8 or not all(b in '01' for b in ciphertext):
            raise ValueError("暴力破解需要8-bit密文")

        # 显示进度条
        self.progress_bar.grid()
        self.progress_var.set(0)
        self.status_label.config(text="正在暴力破解...")

        # 在新线程中执行暴力破解，避免阻塞GUI
        thread = threading.Thread(target=self._run_brute_force, args=(plaintext, ciphertext))
        thread.start()

    except Exception as e:
        messagebox.showerror("错误", str(e))
        self.status_label.config(text="暴力破解失败！")

def _run_brute_force(self, plaintext, ciphertext):
    """在后台线程中运行暴力破解"""
    def update_progress(progress, elapsed_time, found_count):
        self.progress_var.set(progress)
        self.status_label.config(text=f"暴力破解中... {progress:.1f}% | 已找到 {found_count} 个密钥 | 耗时 {elapsed_time:.2f}s")

    found_keys, total_time = brute_force_attack(self.sdes, plaintext, ciphertext, update_progress)

    # 更新UI
    self.root.after(0, self._update_brute_force_ui, found_keys, total_time)

def _update_brute_force_ui(self, found_keys, total_time):
    """更新暴力破解结果到UI"""
    self.progress_bar.grid_remove()
    if found_keys:
        result_str = "\n".join(found_keys)
        output = f"暴力破解成功！\n找到 {len(found_keys)} 个密钥:\n{result_str}\n总耗时: {total_time:.2f} 秒"
    else:
        output = "暴力破解失败！未找到任何匹配的密钥。\n总耗时: {total_time:.2f} 秒"

    self.output_text.delete(1.0, tk.END)
    self.output_text.insert(tk.END, output)
    self.status_label.config(text="暴力破解完成！")

def closure_test_action(self):
    """执行封闭性测试"""
    try:
        # 生成一个随机明文
        import random
        plaintext = ''.join(random.choice('01') for _ in range(8))
        self.plaintext_entry.delete(0, tk.END)
        self.plaintext_entry.insert(0, plaintext)

        # 生成一个随机密钥
        key = ''.join(random.choice('01') for _ in range(10))
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key)

        # 计算密文
        self.sdes.set_key(key)
        ciphertext = self.sdes.encrypt(plaintext)

        # 尝试寻找另一个不同的密钥，使其加密同一个明文得到相同的密文
        other_keys = []
        for i in range(2**10):
            test_key = format(i, '010b')
            if test_key == key:
                continue  # 跳过原始密钥
            self.sdes.set_key(test_key)
            test_ciphertext = self.sdes.encrypt(plaintext)
            if test_ciphertext == ciphertext:
                other_keys.append(test_key)

        # 输出结果
        output = f"=== 封闭性测试 ===\n"
        output += f"随机明文: {plaintext}\n"
        output += f"原始密钥: {key}\n"
        output += f"原始密文: {ciphertext}\n\n"
        if other_keys:
            output += f"发现 {len(other_keys)} 个不同的密钥可以产生相同密文:\n"
            output += "\n".join(other_keys)
            output += "\n\n⚠️ 结论: S-DES 不具备完美单向性，存在密钥碰撞。"
        else:
            output += "未找到其他能产生相同密文的密钥。\n\n✅ 结论: 在此测试中未发现密钥碰撞。"

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, output)
        self.status_label.config(text="封闭性测试完成！")

    except Exception as e:
        messagebox.showerror("错误", str(e))
        self.status_label.config(text="封闭性测试失败！")