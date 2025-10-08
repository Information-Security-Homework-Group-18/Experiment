# ============================
# S-DES 算法核心实现
# ============================

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time


class S_DES:
    """S-DES 加密解密算法类，实现标准版简化 DES 算法"""

    # 固定置换表定义
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]  # 10位密钥初始置换表
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]  # 8位子密钥压缩置换表
    IP = [2, 6, 3, 1, 4, 8, 5, 7]  # 初始置换表
    IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]  # 最终逆置换表
    EPBOX = [4, 1, 2, 3, 2, 3, 4, 1]  # 扩展置换表
    SPBOX = [2, 4, 3, 1]  # 置换盒
    LEFT_SHIFT1 = [2, 3, 4, 5, 1]  # 左移1位
    LEFT_SHIFT2 = [3, 4, 5, 1, 2]  # 左移2位

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
        """初始化S-DES算法实例，包含密钥和子密钥存储"""
        self.key = None  # 存储原始10位密钥（列表形式）
        self.subkeys = []  # 存储生成的两个8位子密钥 [k1, k2]（列表形式）

    @staticmethod
    def permute(block, permutation):
        """按置换表对数据块进行置换"""
        return [block[i - 1] for i in permutation]

    @staticmethod
    def left_shift(block, shift_table):
        """按移位表进行左移"""
        return [block[i - 1] for i in shift_table]

    def set_key(self, key_str):
        """设置并验证加密密钥

        Args:
            key_str (str): 10位二进制字符串格式的密钥

        Raises:
            ValueError: 当输入不符合10位二进制格式时抛出
        """
        if len(key_str) != 10 or not all(b in '01' for b in key_str):
            raise ValueError("密钥必须是10位二进制字符串")
        self.key = [int(bit) for bit in key_str]
        self._generate_subkeys()

    def _generate_subkeys(self):
        """根据初始密钥生成两轮加密所需的子密钥"""
        # P10置换
        p10_key = self.permute(self.key, self.P10)

        # 分为左右两部分
        left = p10_key[:5]
        right = p10_key[5:]

        # 生成k1
        left1 = self.left_shift(left, self.LEFT_SHIFT1)
        right1 = self.left_shift(right, self.LEFT_SHIFT1)
        k1 = self.permute(left1 + right1, self.P8)

        # 生成k2
        left2 = self.left_shift(left1, self.LEFT_SHIFT2)
        right2 = self.left_shift(right1, self.LEFT_SHIFT2)
        k2 = self.permute(left2 + right2, self.P8)

        self.subkeys = [k1, k2]

    @staticmethod
    def _xor(a, b):
        """对两个等长二进制列表执行按位异或操作"""
        return [a[i] ^ b[i] for i in range(len(a))]

    def _sbox_lookup(self, sbox, input_bits):
        """在指定S-Box中查找对应的输出值"""
        row = input_bits[0] * 2 + input_bits[3]
        col = input_bits[1] * 2 + input_bits[2]
        value = sbox[row][col]
        return [(value >> 1) & 1, value & 1]

    def _f_function(self, right, subkey):
        """Feistel函数F(R, K)实现"""
        # 扩展置换
        expanded = self.permute(right, self.EPBOX)

        # 与子密钥异或
        xor_result = self._xor(expanded, subkey)

        # S盒替换
        s1_input = xor_result[:4]
        s2_input = xor_result[4:]

        # 计算S1盒输出
        s1_row = s1_input[0] * 2 + s1_input[3]
        s1_col = s1_input[1] * 2 + s1_input[2]
        s1_out = self.SBOX1[s1_row][s1_col]
        s1_bits = [(s1_out >> 1) & 1, s1_out & 1]

        # 计算S2盒输出
        s2_row = s2_input[0] * 2 + s2_input[3]
        s2_col = s2_input[1] * 2 + s2_input[2]
        s2_out = self.SBOX2[s2_row][s2_col]
        s2_bits = [(s2_out >> 1) & 1, s2_out & 1]

        # SP盒置换
        sp_input = s1_bits + s2_bits
        sp_output = self.permute(sp_input, self.SPBOX)

        return sp_output

    def encrypt(self, plaintext_str):
        """加密8位二进制明文

        Args:
            plaintext_str (str): 8位二进制明文字符串

        Returns:
            str: 8位二进制密文字符串

        Raises:
            ValueError: 输入格式不符合要求时抛出
        """
        if len(plaintext_str) != 8 or not all(b in '01' for b in plaintext_str):
            raise ValueError("明文必须是8位二进制字符串")

        # 转换为二进制列表
        plaintext = [int(bit) for bit in plaintext_str]

        # 生成子密钥
        k1, k2 = self.subkeys

        # 初始置换
        ip_result = self.permute(plaintext, self.IP)
        left, right = ip_result[:4], ip_result[4:]

        # 第一轮Feistel网络
        f_output = self._f_function(right, k1)
        new_left = self._xor(left, f_output)
        new_right = right

        # 交换
        left, right = new_right, new_left

        # 第二轮Feistel网络
        f_output = self._f_function(right, k2)
        new_left = self._xor(left, f_output)
        new_right = right

        # 组合并进行最终置换
        pre_output = new_left + new_right
        ciphertext = self.permute(pre_output, self.IP_INV)

        # 转换为字符串返回
        return ''.join(str(bit) for bit in ciphertext)

    def decrypt(self, ciphertext_str):
        """解密8位二进制密文

        Args:
            ciphertext_str (str): 8位二进制密文字符串

        Returns:
            str: 8位二进制明文字符串

        Raises:
            ValueError: 输入格式不符合要求时抛出
        """
        if len(ciphertext_str) != 8 or not all(b in '01' for b in ciphertext_str):
            raise ValueError("密文必须是8位二进制字符串")

        # 转换为二进制列表
        ciphertext = [int(bit) for bit in ciphertext_str]

        # 生成子密钥
        k1, k2 = self.subkeys

        # 初始置换
        ip_result = self.permute(ciphertext, self.IP)
        left, right = ip_result[:4], ip_result[4:]

        # 第一轮Feistel网络（使用k2）
        f_output = self._f_function(right, k2)
        new_left = self._xor(left, f_output)
        new_right = right

        # 交换
        left, right = new_right, new_left

        # 第二轮Feistel网络（使用k1）
        f_output = self._f_function(right, k1)
        new_left = self._xor(left, f_output)
        new_right = right

        # 组合并进行最终置换
        pre_output = new_left + new_right
        plaintext = self.permute(pre_output, self.IP_INV)

        # 转换为字符串返回
        return ''.join(str(bit) for bit in plaintext)

    def encrypt_ascii(self, ascii_text):
        """ASCII字符串加密处理

        Args:
            ascii_text (str): 普通ASCII字符串

        Returns:
            str: 每个字符对应的8位二进制密文拼接结果
        """
        result = []
        for char in ascii_text:
            # 将字符转换为8位二进制字符串
            byte_str = format(ord(char), '08b')
            # 加密并添加到结果
            encrypted_byte = self.encrypt(byte_str)
            result.append(encrypted_byte)
        return ''.join(result)

    def decrypt_ascii(self, binary_string):
        """ASCII字符串解密处理

        Args:
            binary_string (str): 8的倍数长度的二进制字符串

        Returns:
            str: 解密后的ASCII字符串

        Raises:
            ValueError: 输入长度不是8的倍数时抛出
        """
        if len(binary_string) % 8 != 0:
            raise ValueError("输入的二进制字符串长度必须是8的倍数")

        result = []
        for i in range(0, len(binary_string), 8):
            byte_str = binary_string[i:i + 8]
            decrypted_byte = self.decrypt(byte_str)
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
    """暴力破解S-DES密钥

    Args:
        sdes_instance (S_DES): S-DES算法实例
        known_plaintext (str): 已知明文（8位二进制）
        known_ciphertext (str): 对应的密文（8位二进制）
        progress_callback (function): 进度回调函数

    Returns:
        Tuple[List[str], float]: 匹配密钥列表和破解耗时（秒）
    """
    found_keys = []
    total_keys = 2**10  # 1024个可能密钥
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
        # 进度更新
        if progress_callback and i % 100 == 0:
            elapsed_time = time.time() - start_time
            progress = (i + 1) / total_keys * 100
            progress_callback(progress, elapsed_time, len(found_keys))

    end_time = time.time()
    return found_keys, end_time - start_time


# ============================
# GUI 主窗口
# ============================

class S_DESGUI:
    """S-DES算法图形化操作界面"""

    def __init__(self, root):
        """初始化GUI界面

        Args:
            root (Tk): Tkinter主窗口对象
        """
        self.root = root
        self.root.title("S-DES 加密解密工具")
        self.root.geometry("800x600")
        self.sdes = S_DES()
        self.create_widgets()

    def create_widgets(self):
        """创建并布局所有界面控件"""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # 标题
        title_label = ttk.Label(main_frame, text="S-DES 算法实现", font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=10)

        # 密钥输入
        ttk.Label(main_frame, text="密钥 (10-bit):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.key_entry = ttk.Entry(main_frame, width=15)
        self.key_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        self.key_entry.insert(0, "1010000010")  # 默认测试密钥

        # 明文输入
        ttk.Label(main_frame, text="明文 (8-bit 或 ASCII):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.plaintext_entry = ttk.Entry(main_frame, width=40)
        self.plaintext_entry.grid(row=2, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=5, pady=5)
        self.plaintext_entry.insert(0, "00000000")  # 默认测试明文

        # 操作按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=3, pady=10)

        ttk.Button(button_frame, text="加密", command=self.encrypt_action).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="解密", command=self.decrypt_action).grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="暴力破解", command=self.brute_force_action).grid(row=0, column=2, padx=5)
        ttk.Button(button_frame, text="封闭性测试", command=self.closure_test_action).grid(row=0, column=3, padx=5)

        # 输出区域
        ttk.Label(main_frame, text="输出:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
        self.output_text = scrolledtext.ScrolledText(main_frame, width=70, height=15, wrap=tk.WORD)
        self.output_text.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)

        # 进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), padx=5, pady=5)
        self.progress_bar.grid_remove()  # 默认隐藏

        # 状态提示
        self.status_label = ttk.Label(main_frame, text="准备就绪...")
        self.status_label.grid(row=7, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)

        # 窗口布局配置
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(5, weight=1)

    def encrypt_action(self):
        """执行加密操作并显示结果"""
        try:
            key = self.key_entry.get().strip()
            plaintext = self.plaintext_entry.get().strip()
            self.sdes.set_key(key)

            # 自动识别输入类型
            if len(plaintext) == 8 and all(b in '01' for b in plaintext):
                ciphertext = self.sdes.encrypt(plaintext)
                output = f"明文: {plaintext}\n密文: {ciphertext}"
            else:
                ciphertext_binary = self.sdes.encrypt_ascii(plaintext)
                chunks = [ciphertext_binary[i:i + 8] for i in range(0, len(ciphertext_binary), 8)]
                ciphertext_display = ' '.join(chunks)

                # 添加ASCII密文输出
                ascii_ciphertext = ""
                try:
                    for i in range(0, len(ciphertext_binary), 8):
                        byte = ciphertext_binary[i:i + 8]
                        ascii_ciphertext += chr(int(byte, 2))
                    output = f"明文 (ASCII): {plaintext}\n密文 (二进制): {ciphertext_display}\n密文 (ASCII): {ascii_ciphertext}\n"
                except ValueError:
                    output = f"明文 (ASCII): {plaintext}\n密文 (二进制): {ciphertext_display}\n密文 (ASCII): [包含非可打印字符]\n"

            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, output)
            self.status_label.config(text="加密成功！")
        except Exception as e:
            messagebox.showerror("错误", str(e))
            self.status_label.config(text="加密失败！")

    def decrypt_action(self):
        """执行解密操作并显示结果"""
        try:
            key = self.key_entry.get().strip()
            ciphertext = self.plaintext_entry.get().strip()
            self.sdes.set_key(key)

            # 自动识别输入类型
            if len(ciphertext) == 8 and all(b in '01' for b in ciphertext):
                plaintext = self.sdes.decrypt(ciphertext)
                output = f"密文: {ciphertext}\n明文: {plaintext}"
            elif len(ciphertext) > 0 and all(b in '01' for b in ciphertext) and len(ciphertext) % 8 == 0:
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
        """启动暴力破解操作"""
        try:
            plaintext = self.plaintext_entry.get().strip()
            output_content = self.output_text.get("1.0", tk.END).strip()
            lines = output_content.split('\n')

            # 提取密文
            if len(lines) < 2:
                raise ValueError("请先执行加密操作以获得密文")
            ciphertext_line = lines[1]
            if not ciphertext_line.startswith("密文: "):
                raise ValueError("无法从输出中提取密文，请先执行加密操作")
            ciphertext = ciphertext_line.split(": ")[1].strip()

            # 参数验证
            if len(plaintext) != 8 or not all(b in '01' for b in plaintext):
                raise ValueError("暴力破解需要8-bit明文")
            if len(ciphertext) != 8 or not all(b in '01' for b in ciphertext):
                raise ValueError("暴力破解需要8-bit密文")

            # 显示进度条
            self.progress_bar.grid()
            self.progress_var.set(0)
            self.status_label.config(text="正在暴力破解...")

            # 异步执行破解
            thread = threading.Thread(target=self._run_brute_force, args=(plaintext, ciphertext))
            thread.start()
        except Exception as e:
            messagebox.showerror("错误", str(e))
            self.status_label.config(text="暴力破解失败！")

    def _run_brute_force(self, plaintext, ciphertext):
        """后台线程执行暴力破解"""
        def update_progress(progress, elapsed_time, found_count):
            self.progress_var.set(progress)
            self.status_label.config(text=f"暴力破解中... {progress:.1f}% | 已找到 {found_count} 个密钥 | 耗时 {elapsed_time:.2f}s")

        found_keys, total_time = brute_force_attack(self.sdes, plaintext, ciphertext, update_progress)
        self.root.after(0, self._update_brute_force_ui, found_keys, total_time)

    def _update_brute_force_ui(self, found_keys, total_time):
        """更新暴力破解结果到UI"""
        self.progress_bar.grid_remove()
        if found_keys:
            result_str = "\n".join(found_keys)
            output = f"暴力破解成功！\n找到 {len(found_keys)} 个密钥:\n{result_str}\n总耗时: {total_time:.2f} 秒"
        else:
            output = f"暴力破解失败！未找到任何匹配的密钥。\n总耗时: {total_time:.2f} 秒"
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, output)
        self.status_label.config(text="暴力破解完成！")

    def closure_test_action(self):
        """执行算法封闭性测试"""
        try:
            import random
            plaintext = ''.join(random.choice('01') for _ in range(8))
            self.plaintext_entry.delete(0, tk.END)
            self.plaintext_entry.insert(0, plaintext)

            key = ''.join(random.choice('01') for _ in range(10))
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, key)

            self.sdes.set_key(key)
            ciphertext = self.sdes.encrypt(plaintext)

            # 寻找其他可能产生相同密文的密钥
            other_keys = []
            for i in range(2**10):
                test_key = format(i, '010b')
                if test_key == key:
                    continue
                self.sdes.set_key(test_key)
                test_ciphertext = self.sdes.encrypt(plaintext)
                if test_ciphertext == ciphertext:
                    other_keys.append(test_key)

            # 生成测试报告
            output = f"=== 封闭性测试 ===\n"
            output += f"随机明文: {plaintext}\n"
            output += f"原始密钥: {key}\n"
            output += f"原始密文: {ciphertext}\n"
            if other_keys:
                output += f"发现 {len(other_keys)} 个不同的密钥可以产生相同密文:\n"
                output += "\n".join(other_keys)
                output += "\n⚠️ 结论: S-DES 不具备完美单向性，存在密钥碰撞。"
            else:
                output += "未找到其他能产生相同密文的密钥。\n✅ 结论: 在此测试中未发现密钥碰撞。"

            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, output)
            self.status_label.config(text="封闭性测试完成！")
        except Exception as e:
            messagebox.showerror("错误", str(e))
            self.status_label.config(text="封闭性测试失败！")


# ============================
# 主程序入口
# ============================

if __name__ == "__main__":
    root = tk.Tk()
    app = S_DESGUI(root)
    root.mainloop()
