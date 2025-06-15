import base64
import json
import os
import re
import sys
import threading
import time
from copy import deepcopy
from functools import wraps
import ddddocr
import requests
from Cryptodome.Cipher import AES
from urllib3.exceptions import InsecureRequestWarning

# --- 配置与常量 ---
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
WORKER_THREAD_COUNT = 8
RETRY_DELAY = 0.5
BASE_URL = "https://icourses.jlu.edu.cn/xsxk"
MAX_RETRIES = -1 # -1表示无限重试

class TermColor:
    """终端输出颜色定义"""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'

try:
    ocr = ddddocr.DdddOcr()
except Exception as e:
    print(f"{TermColor.RED}ddddocr (验证码识别库) 初始化失败: {e}{TermColor.ENDC}")
    sys.exit(1)

def strip_ansi(s: str) -> str:
    """从字符串中移除ANSI转义序列（颜色代码）。"""
    return re.sub(r'\033\[[0-9;]*m', '', s)

def get_display_width(s: str) -> int:
    """计算字符串的显示宽度，会特殊处理中日韩等全宽字符。"""
    width = 0
    for char in s:
        if  '\u4e00' <= char <= '\u9fff' or \
            '\u3040' <= char <= '\u309f' or \
            '\u30a0' <= char <= '\u30ff':
            width += 2
        else:
            width += 1
    return width

def pkcs7padding(data: bytes, block_size: int = 16) -> bytes:
    """对数据进行 PKCS7 填充"""
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def retry_on_exception(max_retries=MAX_RETRIES, delay=RETRY_DELAY, message="请求失败，正在重试..."):
    """请求异常时自动重试的装饰器"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    retries += 1
                    if max_retries != -1 and retries > max_retries:
                        raise e
                    if message:
                        print(f"{TermColor.YELLOW}{message} ({e}) [第{retries}次重试]{TermColor.ENDC}", flush=True)
                    time.sleep(delay)
        return wrapper
    return decorator

class ApiClient:
    """负责所有与服务器的HTTP通信"""
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36 Edg/103.0.1264.62',
        })
        self.token = None
        self.batch_id = None

    @retry_on_exception(message="获取AES Key失败")
    def _get_aes_key(self) -> str:
        url = "https://icourses.jlu.edu.cn/"
        response = self.session.get(url, verify=False, timeout=10)
        response.raise_for_status()
        html = response.text
        start = html.find('"', html.find('loginVue.loginForm.aesKey')) + 1
        end = html.find('"', start)
        return html[start:end]

    @retry_on_exception(message="获取验证码失败")
    def _get_captcha(self) -> dict:
        url = f"{BASE_URL}/auth/captcha"
        response = self.session.post(url, verify=False, timeout=10)
        response.raise_for_status()
        return response.json()

    @retry_on_exception(message="登录请求失败")
    def login(self, username, password) -> dict:
        aes_key = self._get_aes_key().encode('utf-8')
        encrypted_password = base64.b64encode(
            AES.new(aes_key, AES.MODE_ECB).encrypt(pkcs7padding(password.encode('utf-8')))
        ).decode('utf-8')
        captcha_data = self._get_captcha()
        uuid = captcha_data['data']['uuid']
        captcha_img_b64 = captcha_data['data']['captcha']
        captcha_text = ocr.classification(base64.b64decode(captcha_img_b64.split(',')[1]))
        login_url = f"{BASE_URL}/auth/login"
        payload = {
            'loginname': username, 'password': encrypted_password,
            'captcha': captcha_text, 'uuid': uuid
        }
        response = self.session.post(login_url, data=payload, verify=False, timeout=10)
        response.raise_for_status()
        login_result = response.json()
        if login_result.get('code') == 200:
            self.token = login_result['data']['token']
            self.session.headers.update({'Authorization': self.token})
            return login_result
        else:
            raise Exception(f"登录失败: {login_result.get('msg')}")

    @retry_on_exception(message="设置选课批次失败")
    def set_batch(self, batch_id: str):
        self.batch_id = batch_id
        self.session.headers.update({'batchId': self.batch_id})
        url = f"{BASE_URL}/elective/user"
        payload = {'batchId': self.batch_id}
        response = self.session.post(url, data=payload, verify=False, timeout=10)
        response.raise_for_status()
        if response.json().get('code') != 200:
            raise Exception("设置批次ID时服务器返回非200状态码")
        time.sleep(0.1)
        grab_url = f"{BASE_URL}/elective/grablessons?batchId={self.batch_id}"
        self.session.get(grab_url, verify=False, timeout=10)

    @retry_on_exception(message="获取收藏列表失败")
    def get_favorites(self) -> list:
        url = f"{BASE_URL}/sc/clazz/list"
        response = self.session.post(url, verify=False, timeout=10)
        response.raise_for_status()
        return response.json()['data']

    @retry_on_exception(message="获取已选课程失败")
    def get_selected_courses(self) -> list:
        url = f"{BASE_URL}/elective/select"
        response = self.session.post(url, verify=False, timeout=10)
        response.raise_for_status()
        return response.json()['data']

    def select_course(self, clazz_type: str, clazz_id: str, secret_val: str) -> dict:
        @retry_on_exception(max_retries=MAX_RETRIES)
        def do_request():
            url = f"{BASE_URL}/sc/clazz/addxk"
            payload = {'clazzType': clazz_type, 'clazzId': clazz_id, 'secretVal': secret_val}
            response = self.session.post(url, data=payload, verify=False, timeout=5)
            response.raise_for_status()
            return response.json()
        return do_request()

# --- 主业务逻辑 ---
class CourseSelector:
    def __init__(self, api_client: ApiClient, try_if_full: bool = True):
        self.api = api_client
        self.try_if_capacity_full = try_if_full
        self.courses = {}
        self.lock = threading.Lock()
        self.shutdown_event = threading.Event()
        self.is_first_display = True
        self.relogin_required = threading.Event()
        self.threads = []

        self.status_map = {
            "PENDING": f"{TermColor.BLUE}等待开始{TermColor.ENDC}",
            "NETWORK_ERROR": f"{TermColor.YELLOW}网络中断{TermColor.ENDC}",
            "SUCCESS": f"{TermColor.GREEN}已选上 ✓{TermColor.ENDC}",
            "ALREADY_SELECTED": f"{TermColor.GREEN}已在结果中{TermColor.ENDC}",
            "CAPACITY_FULL": f"{TermColor.RED}课容量已满{TermColor.ENDC}",
            "NOT_STARTED": f"{TermColor.BLUE}选课未开始{TermColor.ENDC}"
        }

    def _display_status(self):
        with self.lock:
            if not self.courses:
                return
            if self.is_first_display:
                sys.stdout.write(f"\n" * (len(self.courses) + 2))
                self.is_first_display = False
            num_lines = len(self.courses) + 2
            sys.stdout.write(f'\033[{num_lines}A')
            max_name_width = 0
            for details in self.courses.values():
                display_name = f"{details['name']}({details['teacher']})"
                width = get_display_width(display_name)
                if width > max_name_width:
                    max_name_width = width
            total_requests = sum(d['count'] for d in self.courses.values())
            sys.stdout.write(f"总请求次数: {TermColor.GREEN}{total_requests:<10}{TermColor.ENDC}\033[K\n")
            sys.stdout.write("=" * 70 + "\033[K\n")
            for details in self.courses.values():
                display_name = f"{details['name']}({details['teacher']})"
                name_padding = ' ' * (max_name_width - get_display_width(display_name))
                status_text = self.status_map.get(details['status'], details['last_status_text'])
                msg = f" ({details['msg']})" if details['msg'] else ""
                count_text = f"请求: {details['count']}"
                line = f"[{display_name}]{name_padding}  [{status_text}]  {count_text:<15}{msg}\033[K\n"
                sys.stdout.write(line)
            sys.stdout.flush()

    def _worker(self, course: dict):
        thread_api = deepcopy(self.api)
        clazz_id = course['JXBID']
        
        while not self.shutdown_event.is_set():
            try:
                if self.relogin_required.is_set():
                    time.sleep(1)
                    continue
                response = thread_api.select_course(
                    course['teachingClassType'], clazz_id, course['secretVal']
                )
                code, msg = response.get('code'), response.get('msg', '未知响应')
                new_status, status_msg = None, ""
                if code == 200: new_status = "SUCCESS"
                elif '已在选课结果中' in msg: new_status = "ALREADY_SELECTED"
                elif '课容量已满' in msg: new_status = "CAPACITY_FULL"
                elif '暂未开始' in msg: new_status = "NOT_STARTED"
                else:
                    self.relogin_required.set()
                    continue
                with self.lock:
                    self.courses[clazz_id]['count'] += 1
                    if new_status:
                        self.courses[clazz_id]['status'] = new_status
                        self.courses[clazz_id]['msg'] = status_msg
                        self.courses[clazz_id]['last_status_text'] = self.status_map.get(new_status)
            except Exception:
                with self.lock:
                    self.courses[clazz_id]['status'] = "NETWORK_ERROR"
                    self.courses[clazz_id]['last_status_text'] = self.status_map.get("NETWORK_ERROR")
                self.relogin_required.set()
                time.sleep(1)

    def run(self) -> bool:
        display_thread = threading.Thread(target=self._display_refresher)
        display_thread.daemon = True
        display_thread.start()

        favorite_courses = self.api.get_favorites()
        if not favorite_courses:
            print("未能获取到收藏列表或收藏夹为空。")
            return False

        with self.lock:
            for course in favorite_courses:
                initial_status = "PENDING"
                self.courses[course['JXBID']] = {
                    'name': course['KCM'],
                    'teacher': course['SKJS'], 
                    'status': initial_status,
                    'msg': '',
                    'count': 0,
                    'last_status_text': self.status_map.get(initial_status)
                }
        
        sys.stdout.write("\033[?25l")
        time.sleep(0.5)

        for course in favorite_courses:
            for _ in range(WORKER_THREAD_COUNT):
                thread = threading.Thread(target=self._worker, args=(course,))
                self.threads.append(thread)
                thread.start()
        
        while any(t.is_alive() for t in self.threads):
            if self.relogin_required.is_set():
                self.shutdown_event.set()
                break
            time.sleep(0.5)
        
        for t in self.threads:
            t.join()

        self.shutdown_event.set()
        
        if self.relogin_required.is_set():
            return True

        self._display_status()
        sys.stdout.write("\033[?25h")
        return False

    def _display_refresher(self):
        while not self.shutdown_event.is_set():
            self._display_status()
            time.sleep(0.1)

def load_config():
    """从同目录下的 config.json 文件加载配置。"""
    CONFIG_FILE = "config.json"
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            print(f"检测到配置文件 '{CONFIG_FILE}'，正在读取...")
            return json.load(f)
    except FileNotFoundError:
        # 配置文件不存在是正常情况，返回空字典即可
        return {}
    except (json.JSONDecodeError, TypeError):
        print(f"{TermColor.YELLOW}警告: 配置文件 '{CONFIG_FILE}' 格式错误或内容非JSON对象，已忽略。{TermColor.ENDC}")
        return {}

def main():
    # 1. 从文件加载配置
    config_from_file = load_config()

    # 2. 检查是否提供了足够的命令行参数
    cli_args_provided = len(sys.argv) >= 4

    # 3. 优先级合并：命令行 > 配置文件
    if cli_args_provided:
        print("检测到命令行参数，将优先使用命令行参数进行本次运行。")
        sleep(1)
        username = sys.argv[1]
        password = sys.argv[2]
        batch_idx_str = sys.argv[3]
        run_in_loop = len(sys.argv) > 4 and sys.argv[4].lower() == 'loop'
    else:
        print("未提供命令行参数，将尝试从 config.json 文件中读取配置。")
        time.sleep(1)
        username = config_from_file.get('username')
        password = config_from_file.get('password')
        # .get()方法可以安全地处理不存在的键
        batch_idx_str = config_from_file.get('batch_index')
        run_in_loop = config_from_file.get('loop', False)

    # 4. 验证参数完整性并提供引导
    try:
        batch_idx = int(batch_idx_str) if batch_idx_str is not None else None
    except (ValueError, TypeError):
        batch_idx = None # 如果批次索引不是有效数字，则视为无效

    if not all([username, password, batch_idx is not None]):
        print("\n" + "="*60)
        print(f"{TermColor.RED}错误：缺少必要的配置信息（学号、密码或批次索引）。{TermColor.ENDC}")
        print("\n请通过以下两种方式之一提供配置：\n")
        print(f"{TermColor.YELLOW}方式一：通过命令行参数（单次运行，优先级最高）{TermColor.ENDC}")
        print(f"  用法: python {sys.argv[0]} <学号> <密码> <批次索引> [loop]\n")
        print(f"{TermColor.YELLOW}方式二：通过配置文件（推荐，可保存配置）{TermColor.ENDC}")
        print(f"  在脚本同目录下创建一个名为 'config.json' 的文件，内容模板如下：")
        print(TermColor.GREEN + """
{
    "username": "你的学号",
    "password": "你的密码",
    "batch_index": 0,
    "loop": true
}
""" + TermColor.ENDC)
        print("\n说明:")
        print("  - batch_index: 0 代表第一个批次，1 代表第二个，以此类推。")
        print("  - loop: true 代表持续循环抢课（防止数据回滚），false 代表抢完一轮后停止。")
        print("="*60)
        sys.exit(1)

    selector = None
    try:
        while True:
            try:
                client = ApiClient()
                print("正在登录...")
                login_data = client.login(username, password)
                student_info = login_data['data']['student']
                os.system('cls' if os.name == 'nt' else 'clear')
                print(f"{TermColor.GREEN}登录成功！{TermColor.ENDC}")
                print("="*40)
                print(f"学号: {student_info['XH']}")
                print(f"姓名: {student_info['XM']}")
                print(f"专业: {student_info['ZYMC']}")
                print("="*40)
                
                batches = student_info['electiveBatchList']
                if not batches or batch_idx >= len(batches):
                    print(f"{TermColor.RED}错误: 无效的批次索引 {batch_idx}。可用批次数: {len(batches)}{TermColor.ENDC}")
                    if batches:
                        print("可用批次列表:")
                        for i, b in enumerate(batches):
                            print(f"  索引 {i}: {b['name']}")
                    break
                
                target_batch = batches[batch_idx]
                print("选定的选课批次:")
                print(f"名称: {TermColor.YELLOW}{target_batch['name']}{TermColor.ENDC}")
                print("=" * 40)

                client.set_batch(target_batch['code'])
                
                selector = CourseSelector(client, try_if_full=True)
                
                relogin_needed = selector.run()

                if relogin_needed:
                    print(f"{TermColor.YELLOW}检测到错误或会话过期，1秒后将自动重新登录并继续...{TermColor.ENDC}")
                    time.sleep(1)
                    continue

                print("\n本轮所有课程状态已稳定。")
                
                if not run_in_loop:
                    print("非loop模式，程序运行结束。")
                    break
                else:
                    print(f"\n{TermColor.BLUE}Loop模式开启，5秒后将开始下一轮循环... (按 Ctrl+C 退出){TermColor.ENDC}")
                    time.sleep(5)
            
            except Exception as e:
                print(f"\n{TermColor.RED}发生严重错误: {e}{TermColor.ENDC}")
                print(f"{TermColor.YELLOW}1秒后将自动尝试重新登录并继续...{TermColor.ENDC}")
                time.sleep(1)

    except KeyboardInterrupt:
        print(f"\n{TermColor.YELLOW}捕获到 Ctrl+C，正在通知所有线程停止...{TermColor.ENDC}")
        if selector:
            selector.shutdown_event.set()
        time.sleep(1)
        print(f"程序已安全退出。{TermColor.ENDC}")

    finally:
        sys.stdout.write("\033[?25h")

if __name__ == '__main__':
    main()