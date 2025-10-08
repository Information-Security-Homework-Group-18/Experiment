import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time

# ============================
# S-DES 算法核心实现
# ============================

class S_DES:
    """S-DES 加密解密算法类，实现课程标准版简化 DES 算法"""

    # 固定置换表定义
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]        # 10位密钥初始置换表，用于密钥扩展
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]               # 8位子密钥压缩置换表，从10位中间密钥生成8位子密钥
    IP = [2, 6, 3, 1, 4, 8, 5, 7]                # 初始置换表，用于明文预处理
    IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]            # 最终逆置换表，用于输出密文/明文
    EPBOX = [4, 1, 2, 3, 2, 3, 4, 1]             # 扩展置换表，将4位右半部分扩展为8位
    SPBOX = [2, 4, 3, 1]                         # 置换盒，对S盒输出结果进行位置重排

    # S-Box 查找表（4x4矩阵）
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
        self.key = None          # 存储原始10位密钥
        self.subkeys = []        # 存储生成的两个8位子密钥 [k1, k2]

    def set_key(self, key_str):
        """设置并验证加密密钥

        Args:
            key_str (str): 10位二进制字符串格式的密钥

        Raises:
            ValueError: 当输入不符合10位二进制格式时抛出
        """
        if len(key_str) != 10 or not all(b in '01' for b in key_str):
            raise ValueError("密钥必须是10位二进制字符串")
        self.key = key_str
        self._generate_subkeys()

    def _generate_subkeys(self):
        """根据初始密钥生成两轮加密所需的子密钥

        执行流程：
        1. 应用P10置换进行密钥初始打乱
        2. 分割为左右两部分并分别进行左移操作
        3. 通过P8置换生成第一个子密钥k1
        4. 对移位后的结果再次左移并生成第二个子密钥k2
        """
        # 步骤1: P10置换
        p10_result = ''.join([self.key[i - 1] for i in self.P10])

        # 步骤2: 分割为左右两部分
        left_half = p10_result[:5]
        right_half = p10_result[5:]

        # 步骤3: 第一次左移1位
        left_shifted_1 = left_half[1:] + left_half[0]
        right_shifted_1 = right_half[1:] + right_half[0]

        # 调试输出：验证第一次左移
        print(f"[DEBUG] 第一次左移后: 左半部分={left_shifted_1}, 右半部分={right_shifted_1}")

        # 步骤4: 生成k1
        merged_1 = left_shifted_1 + right_shifted_1
        k1 = ''.join([merged_1[i - 1] for i in self.P8])

        # 步骤5: 第二次左移2位
        left_shifted_2 = left_shifted_1[2:] + left_shifted_1[:2]
        right_shifted_2 = right_shifted_1[2:] + right_shifted_1[:2]

        # 调试输出：验证第二次左移
        print(f"[DEBUG] 第二次左移后: 左半部分={left_shifted_2}, 右半部分={right_shifted_2}")

        # 步骤6: 生成k2
        merged_2 = left_shifted_2 + right_shifted_2
        k2 = ''.join([merged_2[i - 1] for i in self.P8])

        self.subkeys = [k1, k2]

    def _xor(self, a, b):
        """对两个等长二进制字符串执行按位异或操作

        Args:
            a (str): 第一个二进制字符串
            b (str): 第二个二进制字符串

        Returns:
            str: 异或结果的二进制字符串
        """
        return ''.join('1' if x != y else '0' for x, y in zip(a, b))

    def _sbox_lookup(self, sbox, input_bits):
        """在指定S-Box中查找对应的输出值

        S-Box 查找规则：
        - 前后两位确定行号（二进制转十进制）
        - 中间两位确定列号（二进制转十进制）
        - 返回对应位置的值并转换为2位二进制

        Args:
            sbox (List[List[int]]): 使用的S-Box查找表
            input_bits (str): 4位输入二进制字符串

        Returns:
            str: 2位二进制输出结果
        """
        row = int(input_bits[0] + input_bits[3], 2)  # 第1位和第4位组成行号
        col = int(input_bits[1] + input_bits[2], 2)  # 第2位和第3位组成列号
        value = sbox[row][col]
        return format(value, '02b')  # 转换为2位二进制输出

    def _f_function(self, right_half, subkey):
        """Feistel函数F(R, K)实现

        执行步骤：
        1. 扩展置换EPBox将4位扩展为8位
        2. 与子密钥进行异或运算
        3. 分为两组4位分别通过不同S-Box
        4. 合并S-Box输出并应用SPBox置换

        Args:
            right_half (str): 4位右半部分数据
            subkey (str): 8位子密钥

        Returns:
            str: 4位函数运算结果
        """
        # 扩展置换
        expanded = ''.join([right_half[i - 1] for i in self.EPBOX])
        # 异或运算
        xor_result = self._xor(expanded, subkey)
        # S-Box 处理
        sbox1_output = self._sbox_lookup(self.SBOX1, xor_result[:4])
        sbox2_output = self._sbox_lookup(self.SBOX2, xor_result[4:])
        # SPBox 置换
        combined = sbox1_output + sbox2_output
        spboxed = ''.join([combined[i - 1] for i in self.SPBOX])
        return spboxed

    def _feistel_round(self, data, subkey):
        """执行单轮Feistel网络结构

        Args:
            data (str): 8位输入数据
            subkey (str): 当前使用的8位子密钥

        Returns:
            str: 8位处理后的输出数据
        """
        left_half = data[:4]
        right_half = data[4:]
        f_output = self._f_function(right_half, subkey)
        new_left = self._xor(left_half, f_output)
        return right_half + new_left  # 自动完成左右交换

    def encrypt(self, plaintext):
        """加密8位二进制明文

        加密流程：
        IP(P) -> F(R,K1) -> SW -> F(R,K2) -> IP^{-1}

        Args:
            plaintext (str): 8位二进制明文字符串

        Returns:
            str: 8位二进制密文字符串

        Raises:
            ValueError: 输入格式不符合要求时抛出
        """
        if len(plaintext) != 8 or not all(b in '01' for b in plaintext):
            raise ValueError("明文必须是8位二进制字符串")

        # 初始置换
        ip_result = ''.join([plaintext[i - 1] for i in self.IP])

        # 第一轮Feistel
        round1_result = self._feistel_round(ip_result, self.subkeys[0])

        # 第二轮Feistel
        round2_result = self._feistel_round(round1_result, self.subkeys[1])

        # 最终逆置换
        ciphertext = ''.join([round2_result[i - 1] for i in self.IP_INV])
        return ciphertext

    def decrypt(self, ciphertext):
        """解密8位二进制密文

        解密流程：
        IP(C) -> F(R,K2) -> SW -> F(R,K1) -> IP^{-1}

        Args:
            ciphertext (str): 8位二进制密文字符串

        Returns:
            str: 8位二进制明文字符串

        Raises:
            ValueError: 输入格式不符合要求时抛出
        """
        if len(ciphertext) != 8 or not all(b in '01' for b in ciphertext):
            raise ValueError("密文必须是8位二进制字符串")

        # 初始置换
        ip_result = ''.join([ciphertext[i - 1] for i in self.IP])

        # 第一轮Feistel（使用k2）
        round1_result = self._feistel_round(ip_result, self.subkeys[1])

        # 第二轮Feistel（使用k1）
        round2_result = self._feistel_round(round1_result, self.subkeys[0])

        # 最终逆置换
        plaintext = ''.join([round2_result[i - 1] for i in self.IP_INV])
        return plaintext

    def encrypt_ascii(self, ascii_text):
        """ASCII字符串加密处理

        Args:
            ascii_text (str): 普通ASCII字符串

        Returns:
            str: 每个字符对应的8位二进制密文拼接结果
        """
        result = []
        for char in ascii_text:
            byte_str = format(ord(char), '08b')
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
            byte_str = binary_string[i:i+8]
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
        self.root.title("S-DES 加密解密工具 (课程标准版)")
        self.root.geometry("800x600")
        self.sdes = S_DES()
        self.create_widgets()

    def create_widgets(self):
        """创建并布局所有界面控件"""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # 标题
        title_label = ttk.Label(main_frame, text="S-DES 算法实现 (课程标准版)", font=("Arial", 16, "bold"))
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
